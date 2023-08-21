#[macro_use]
extern crate log;
extern crate clap;

use clap::Parser;
use std::collections::HashMap;
use std::{mem, io};
use std::error::Error;
use std::net::{SocketAddr, UdpSocket, SocketAddrV4};
use std::str::FromStr;
use smoltcp::wire::{EthernetFrame, Ipv4Address, Ipv4Packet, UdpPacket, IpProtocol, EthernetProtocol, EthernetAddress};
use std::time::Instant;
use dns_parser::RData;
use env_logger::Builder;
use log::LevelFilter;
use quiche::Config;
use dns_parser::rdata::a::Record;
use libc::{socket, recvfrom, PF_PACKET, SOCK_RAW, SOCK_NONBLOCK, c_void, sockaddr_ll, sockaddr, sendto, setsockopt, SOL_SOCKET, SO_BINDTODEVICE, socklen_t};

const MAX_DATAGRAM_SIZE: usize = 1350;
const ETH_TYPE: u16 = 0x0800;

pub fn init_quic_config() -> Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.load_cert_chain_from_pem_file("cert.crt").unwrap();
    config.load_priv_key_from_pem_file("cert.key").unwrap();
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();
    config
}

fn parse_server_name(from: SocketAddr, data: &Vec<u8>, config: &mut Config) -> Option<String> {
    let mut payload = data.clone();
    let hdr: quiche::Header<'_> = match quiche::Header::from_slice(&mut payload, quiche::MAX_CONN_ID_LEN) {
        Ok(v) => v,
        Err(_) => {
            error!("Failed to parse header");
            return None;
        }
    };
    let scid = hdr.scid.clone();
    let mut conn = match quiche::accept(&scid, None, from, config) {
        Ok(v) => v,
        Err(_) => {
            error!("Failed to accept connection");
            return None;
        }
    };
    let recv_info = quiche::RecvInfo { from };
    let _read = match conn.recv_lite(payload.as_mut(), recv_info) {
        Ok(v) => v,
        Err(_) => {
            error!("Failed to recv QUIC packet");
            return None;
        }
    };
    conn.server_name().map(|name| name.to_string())
}

fn dns_query(name: &str, socket: &UdpSocket) {
    let mut builder = dns_parser::Builder::new_query(0, false);
    builder.add_question(name, false, dns_parser::QueryType::A, dns_parser::QueryClass::IN);
    let query = builder.build().unwrap();
    socket.send(&query).unwrap();
}

fn udp_server(interface_index: i32, forward_once: bool) -> Result<(), Box<dyn Error>> {
    let dns_socket = UdpSocket::bind("0.0.0.0:0")?;
    dns_socket.set_nonblocking(true)?;
    dns_socket.connect(SocketAddr::new("127.0.0.1".parse().unwrap(), 8053))?;
    // let client_fd = unsafe {
    //     let fd = socket(PF_PACKET, SOCK_RAW|SOCK_NONBLOCK, ETH_TYPE.to_be() as i32);
    //     let res = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "enp0s8".as_ptr() as *const c_void, 6);
    //     info!("Bind NIC res: {}", res);
    //     fd
    // };
    let raw_fd = unsafe {
        let fd = socket(PF_PACKET, SOCK_RAW|SOCK_NONBLOCK, ETH_TYPE.to_be() as i32);
        let res = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "br0".as_ptr() as *const c_void, 3);
        info!("Bind NIC res: {}", res);
        fd
    };

    let mut forwarding_map: HashMap<String, Vec<((Vec<u8>, u16, sockaddr, isize), SocketAddr)>> = HashMap::new();
    let mut connection_map: HashMap<SocketAddr, String> = HashMap::new();
    let mut resolution_record: HashMap<String, String> = HashMap::new();
    let mut recv_buf: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];
    let mut config: Config = init_quic_config();
    let mut sender_addr: sockaddr_ll = unsafe { mem::zeroed() };
    let mut addr_buf_sz: socklen_t = mem::size_of::<sockaddr_ll>() as socklen_t;
    let mut addr_ptr: *mut sockaddr;
    let mut packet_size: isize;

    let start_ts = Instant::now();

    loop {
        // Step 1, read from the client
        unsafe {
            addr_ptr = mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sender_addr);
            packet_size = recvfrom(raw_fd, recv_buf.as_mut_ptr() as *mut c_void, recv_buf.len(), 0,
                                   addr_ptr as *mut sockaddr, &mut addr_buf_sz);
        }
        if packet_size >= 1200 {
            let mut eth = EthernetFrame::new_checked(recv_buf.clone()).unwrap();
            if eth.ethertype() == EthernetProtocol::Ipv4 {
                let mut ipv4 = match Ipv4Packet::new_checked(eth.payload_mut()) {
                    Ok(v) => v,
                    _ => continue,
                };
                let src = ipv4.src_addr();
                let dst = ipv4.dst_addr();
                let my_ip: Ipv4Address = "192.168.57.12".parse().unwrap();
                if dst == my_ip.into() {
                    if ipv4.protocol() == IpProtocol::Udp {
                        let mut udp = UdpPacket::new_unchecked(ipv4.payload_mut());
                        if udp.dst_port() == 443 {
                            info!("Received {} bytes from {:?}", packet_size, src);

                            // Forward non-first packets directly
                            let addr: SocketAddr = SocketAddrV4::new(src.into(), udp.src_port()).into();
                            if let Some(domain) = connection_map.get(&addr) {
                                if let Some(server_ip) = resolution_record.get(domain) {
                                    // The domain name is already resolved, forward directly.
                                    info!("The domain name is already resolved, forward directly");
                                    let dst = Ipv4Address::from_str(server_ip).unwrap();
                                    udp.fill_checksum(&src.into(), &dst.into());
                                    ipv4.set_dst_addr(dst);
                                    ipv4.fill_checksum();
                                    unsafe {
                                        // let mut sender_addr: sockaddr_ll = mem::zeroed();
                                        // let addr_ptr = mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sender_addr);
                                        let len = sendto(raw_fd, eth.as_ref().as_ptr() as *mut c_void, eth.as_ref().len() as usize, 0,
                                                                addr_ptr as *mut sockaddr, addr_buf_sz);
                                        info!("[{:?}] Forward {}({}) bytes from {} to {}", start_ts.elapsed(), len, eth.as_ref().len(), addr, server_ip)
                                    }
                                } else {
                                    // The domain name is not resovled yet, store to the forwarding map.
                                    info!("The domain name is not resolved yet, store to the forwarding map");
                                    let eths = forwarding_map.entry(domain.clone()).or_insert(Vec::new());
                                    info!("Save {} bytes: {}", eth.as_ref().len(), domain);
                                    unsafe {
                                        eths.push(((eth.as_ref().to_vec(), packet_size as u16, *addr_ptr, addr_buf_sz as isize), addr));
                                    }
                                }
                            // Send DNS query and wait for name resolution before forwarding
                            } else {
                                info!("Send DNS query and wait for name resolution");
                                match parse_server_name(addr, &udp.payload_mut().to_vec(), &mut config) {
                                    Some(domain) => {
                                        let eths = forwarding_map.entry(domain.clone()).or_insert(Vec::new());
                                        unsafe {
                                            eths.push(((eth.as_ref().to_vec(), packet_size as u16, *addr_ptr, addr_buf_sz as isize), addr));
                                        }
                                        info!("Save {} bytes: {}", eth.as_ref().len(), domain);
                                        dns_query(&domain, &dns_socket);
                                    },
                                    _ => { error!("Failed to parse/resolve the initial packet"); }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Step 2, read from the DNS resolver and forward the pending packets
        match dns_socket.recv(&mut recv_buf) {
            Ok(len) => {
                let data = recv_buf[..len].to_vec();
                let response = dns_parser::Packet::parse(&data).unwrap();
                let name = response.questions[0].qname.to_string();
                for answer in response.answers {
                    match answer.data {
                        RData::A(Record(ip)) => {
                            info!("Finish name resolution, {}: {}", name, ip);
                            resolution_record.insert(name.clone(), ip.to_string());
                            // Forward pending packets
                            if let Some(eths) = forwarding_map.get_mut(&name) {
                                for ((eth_buf, packet_size, _, _), addr) in &mut *eths {
                                    connection_map.insert(*addr, name.clone());
                                    let mut eth = EthernetFrame::new_checked(eth_buf.clone()).unwrap();
                                    let eth_src: EthernetAddress = "3a:4d:a7:05:2a:13".parse().unwrap();
                                    eth.set_src_addr(eth_src);
                                    let mut ipv4 = Ipv4Packet::new_checked(eth.payload_mut()).unwrap();
                                    let src = ipv4.src_addr();
                                    let mut udp = UdpPacket::new_checked(ipv4.payload_mut()).unwrap();
                                    udp.fill_checksum(&src.into(), &ip.into());
                                    ipv4.set_dst_addr(ip.into());
                                    ipv4.fill_checksum();
                                    let send_data = eth.as_ref();

                                    // let interface_name = "br0";
                                    // let interface_index = unsafe {
                                    //     libc::if_nametoindex(interface_name.as_ptr() as *const libc::c_char)
                                    // };
                                    info!("NIC index: {}", interface_index);
                                    let destination_mac: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0x00, 0x00];
                                    let sockaddr = libc::sockaddr_ll {
                                        sll_family: libc::AF_PACKET as u16,
                                        sll_protocol: libc::ETH_P_ALL.to_be() as u16,
                                        sll_ifindex: interface_index as i32, 
                                        sll_halen: 6,
                                        sll_addr: destination_mac,
                                        sll_pkttype: 0,
                                        ..unsafe { std::mem::zeroed() }
                                    };
                                    unsafe {
                                        let len = sendto(raw_fd, send_data.as_ptr() as *mut c_void, *packet_size as usize, 0,
                                                          &sockaddr as *const _ as *const libc::sockaddr, 
                                                          std::mem::size_of_val(&sockaddr) as libc::socklen_t);
                                        info!("[{:?}] Forward {}({}) bytes from {} to {}", start_ts.elapsed(), len, packet_size, addr, ip);
                                        if len < 0 {
                                            let error = io::Error::last_os_error();
                                            eprintln!("Error sending packet: {}", error);
                                        }
                                    }
                                }
                                if forward_once {
                                    eths.clear();
                                }
                            }
                            break;
                        }
                        _ => { }
                    }
                }
            },
            _ => { }
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct MyArgs {
    #[arg(short, long)]
    nic_index: i32,
    #[arg(short, long)]
    forward_once: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();
    let args = MyArgs::parse();
    info!("args: {:?}", args);
    info!("Starting QUIC resolver");
    udp_server(args.nic_index, args.forward_once)?;
    Ok(())
}
