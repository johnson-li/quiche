#[macro_use]
extern crate log;
extern crate clap;

use clap::Parser;
use std::collections::HashMap;
use std::{mem, io};
use std::error::Error;
use std::net::{SocketAddr, UdpSocket, SocketAddrV4, Ipv4Addr};
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
const HANDSHAKE_TIMEOUT: u16 = 3000; // in ms
const FORWARDING_TIMES_LIMIT: u16 = 3;

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

struct ForwardingItem {
    eth_buf: Vec<u8>,
    packet_size: u16,
    last_sent_ts: Instant,
    times: u16,
}
type ForwardingMap = HashMap<String, Vec<ForwardingItem>>;

fn forward_packet(item: &mut ForwardingItem, target_ip: Ipv4Addr, interface_index: i32, raw_fd: i32, start_ts: Instant) {
    let mut eth = EthernetFrame::new_checked(item.eth_buf.clone()).unwrap();
    let eth_src: EthernetAddress = "3a:4d:a7:05:2a:13".parse().unwrap();
    eth.set_src_addr(eth_src);
    let mut ipv4 = Ipv4Packet::new_checked(eth.payload_mut()).unwrap();
    let src = ipv4.src_addr();
    let mut udp = UdpPacket::new_checked(ipv4.payload_mut()).unwrap();
    udp.fill_checksum(&src.into(), &target_ip.into());
    ipv4.set_dst_addr(target_ip.into());
    ipv4.fill_checksum();
    let send_data = eth.as_ref();
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
    info!("Send packet to {:?}", target_ip);
    let len = unsafe {
        sendto(raw_fd, send_data.as_ptr() as *mut c_void, 
        item.packet_size as usize, 0,
        &sockaddr as *const _ as *const libc::sockaddr, 
        std::mem::size_of_val(&sockaddr) as libc::socklen_t)
    };
    info!("[{:?}] Forward {}({}) bytes from {} to {}", start_ts.elapsed(), len, item.packet_size, src, target_ip);
    if len < 0 {
        let error = io::Error::last_os_error();
        eprintln!("Error sending packet: {}", error);
    }
    item.times += 1;
    item.last_sent_ts = Instant::now();
}

fn forward_packets(name: &String, forwarding_map: &mut ForwardingMap,
                   interface_index: i32, raw_fd: i32, forward_once: bool, start_ts: Instant, target_ip: Ipv4Addr) {
    if let Some(eths) = forwarding_map.get_mut(name) {
        let mut to_be_del = Vec::new();
        for (pos, item) in eths.iter_mut().enumerate() {
            forward_packet(item, target_ip, interface_index, raw_fd, start_ts);
            if item.times > FORWARDING_TIMES_LIMIT {
                to_be_del.push(pos);
            }
        }
        if forward_once {
            eths.clear();
        } else {
            for pos in to_be_del.iter().rev() {
                eths.remove(*pos);
            }
        }
    }
}

fn add_to_forwarding_map(forwarding_map: &mut ForwardingMap, eth: Vec<u8>, packet_size: isize, domain: &String, times: u16) {
    let eths = forwarding_map.entry(domain.clone()).or_insert(Vec::new());
    eths.push(ForwardingItem { eth_buf: (eth), packet_size: (packet_size as u16), last_sent_ts: (Instant::now()), times: (times) });
}

fn udp_server(interface_index: i32, forward_once: bool) -> Result<(), Box<dyn Error>> {
    let dns_control_socket = UdpSocket::bind("0.0.0.0:0")?;
    dns_control_socket.set_nonblocking(true)?;
    dns_control_socket.connect(SocketAddr::new("127.0.0.1".parse().unwrap(), 8888))?;
    let monitor_socket = UdpSocket::bind("0.0.0.0:8080")?;
    monitor_socket.set_nonblocking(true)?;
    let dns_socket = UdpSocket::bind("0.0.0.0:0")?;
    dns_socket.set_nonblocking(true)?;
    dns_socket.connect(SocketAddr::new("127.0.0.1".parse().unwrap(), 8053))?;
    let raw_fd = unsafe {
        let fd = socket(PF_PACKET, SOCK_RAW|SOCK_NONBLOCK, ETH_TYPE.to_be() as i32);
        let res = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "br0".as_ptr() as *const c_void, 3);
        info!("Bind NIC res: {}", res);
        fd
    };

    let mut forwarding_map: ForwardingMap = HashMap::new();
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
        let packet_recv_ts = Instant::now();
        if packet_size >= 1 {
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
                                    add_to_forwarding_map(&mut forwarding_map, eth.as_ref().to_vec(), packet_size, domain, 1);
                                } else {
                                    // The domain name is not resovled yet, store to the forwarding map.
                                    info!("The domain name is not resolved yet, store to the forwarding map");
                                    add_to_forwarding_map(&mut forwarding_map, eth.as_ref().to_vec(), packet_size, domain, 0);
                                }
                            // Perform name resolution before forwarding
                            } else {
                                match parse_server_name(addr, &udp.payload_mut().to_vec(), &mut config) {
                                    Some(domain) => {
                                        if let Some(server_ip) = resolution_record.get(&domain) {
                                            info!("Domain already resolved, forward directly, delay: {:?}", packet_recv_ts.elapsed());
                                            let dst = Ipv4Address::from_str(server_ip).unwrap();
                                            udp.fill_checksum(&src.into(), &dst.into());
                                            ipv4.set_dst_addr(dst);
                                            ipv4.fill_checksum();
                                            let len = unsafe {
                                                sendto(raw_fd, eth.as_ref().as_ptr() as *mut c_void, eth.as_ref().len() as usize, 0,
                                                       addr_ptr as *mut sockaddr, addr_buf_sz)
                                            };
                                            info!("[{:?}] Forward {}({}) bytes from {} to {}", start_ts.elapsed(), len, eth.as_ref().len(), addr, server_ip);
                                            add_to_forwarding_map(&mut forwarding_map, eth.as_ref().to_vec(), packet_size, &domain, 1);
                                        } else {
                                            info!("Send DNS query and wait for name resolution");
                                            connection_map.insert(addr, domain.clone());
                                            add_to_forwarding_map(&mut forwarding_map, eth.as_ref().to_vec(), packet_size, &domain, 0);
                                            dns_query(&domain, &dns_socket);
                                        }
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
                            forward_packets(&name, &mut forwarding_map, interface_index, raw_fd, forward_once, start_ts, ip);
                            break;
                        }
                        _ => { }
                    }
                }
            },
            _ => { }
        }
    
        // Step 3, read from the QUIC monitor
        match monitor_socket.recv(&mut recv_buf) {
            Ok(len) => {
                if len == 10 {
                    let status = recv_buf[0]; 
                    let port: u16 = ((recv_buf[1] as u16) << 8) | recv_buf[2] as u16;
                    let domain = connection_map.get(&SocketAddr::new("10.0.10.10".parse().unwrap(), port)) ;
                    if let Some(domain) = domain {
                        // Handshake success
                        if status == 1 {
                            info!("QUIC handshake succeeded, port: {}, domain: {:?}", port, domain);
                            forwarding_map.remove(domain);
                        } else if status == 2 {
                            info!("QUIC handshake failed, port: {}, domain: {:?}", port, domain);
                            if let Some(target_ip) = resolution_record.get(domain) {
                                info!("Re-forwarding pending packets of {} to {}", domain, target_ip);
                                forward_packets(domain, &mut forwarding_map, interface_index, raw_fd, forward_once, start_ts, target_ip.parse().unwrap())
                            } else {
                                info!("Name resolution has not completed yet, nothing to do");
                            }
                        } else {
                            error!("Unknown handshake status: {}", status)
                        }
                    } else {
                        error!("Failed to find domain name for port: {}", port);
                    }
                } else {
                    error!("Failed to read from QUIC monitor");
                }
            },
            Err(_) => { },
        }

        // Step 4, check handshake timeout
        for (domain, eths) in forwarding_map.iter_mut() {
            let mut to_be_del = Vec::new();
            let mut make_query = false;
            for (pos, item) in eths.iter_mut().enumerate() {
                if item.last_sent_ts.elapsed().as_millis() > HANDSHAKE_TIMEOUT as u128 {
                    item.last_sent_ts = Instant::now();
                    item.times += 1;
                    make_query = true;
                    if item.times > FORWARDING_TIMES_LIMIT {
                        to_be_del.push(pos);
                    }
                }
            }
            if make_query {
                dns_control_socket.send(domain.as_bytes()).unwrap();
            }
            for pos in to_be_del.iter().rev() {
                eths.remove(*pos);
            }
        } 
        
        // Step 5, re-forward on DNS cache update
        match dns_control_socket.recv(&mut recv_buf) {
            Ok(len) => {
                let data = String::from_utf8(recv_buf[..len].to_vec()).unwrap();
                let data: Vec<&str> = data.split_whitespace().collect();
                let domain = data[0].to_string();
                let target_ip = data[1].to_string();
                info!("Re-forwarding pending packets because of DNS cache update: {} -> {}", domain, target_ip);
                forward_packets(&domain, &mut forwarding_map, interface_index, raw_fd, forward_once, start_ts, target_ip.parse().unwrap())
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
