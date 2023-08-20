#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::mem;
use std::error::Error;
use std::net::{SocketAddr, UdpSocket, IpAddr};
use std::str::FromStr;
use smoltcp::wire::{EthernetFrame, Ipv4Address, Ipv4Packet, UdpPacket, IpProtocol, EthernetProtocol};
use std::time::Instant;
use dns_parser::RData;
use env_logger::Builder;
use log::LevelFilter;
use quiche::Config;
use dns_parser::rdata::a::Record;
use libc::{socket, PF_PACKET, SOCK_RAW, c_void, sockaddr_ll, sockaddr, sendto, setsockopt, SOL_SOCKET, SO_BINDTODEVICE};

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

fn udp_server() -> Result<(), Box<dyn Error>> {
    // Init sockets.
    let client_socket = UdpSocket::bind("0.0.0.0:443")?;
    client_socket.set_nonblocking(true)?;
    let dns_socket = UdpSocket::bind("0.0.0.0:0")?;
    dns_socket.set_nonblocking(true)?;
    dns_socket.connect(SocketAddr::new("127.0.0.1".parse().unwrap(), 8053))?;
    let raw_fd = unsafe {
        let fd = socket(PF_PACKET, SOCK_RAW, ETH_TYPE.to_be() as i32);
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "br0".as_ptr() as *const c_void, 3);
        fd
    };

    let mut forwarding_map: HashMap<String, Vec<(Vec<u8>, SocketAddr)>> = HashMap::new();
    let mut connection_map: HashMap<SocketAddr, String> = HashMap::new();
    let mut resolution_record: HashMap<String, String> = HashMap::new();
    let mut recv_buf: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];
    let mut config: Config = init_quic_config();

    let start_ts = Instant::now();

    loop {
        // Step 1, read from the client
        match client_socket.recv_from(&mut recv_buf) {
            Ok((len, addr)) => {
                let mut eth_buf: Vec<u8> = vec![0; len + 14 + 20 + 8];
                eth_buf[42..].copy_from_slice(&recv_buf[..len]);
                let mut eth = EthernetFrame::new_checked(eth_buf.clone()).unwrap();
                eth.set_ethertype(EthernetProtocol::Ipv4);
                let mut ipv4 = Ipv4Packet::new_checked(eth.payload_mut()).unwrap();
                ipv4.set_version(4);
                ipv4.set_header_len(20);
                ipv4.set_dscp(0x48);
                ipv4.set_ecn(0);
                ipv4.set_total_len(20 + 8 + len as u16);
                ipv4.set_dont_frag(true);
                ipv4.set_hop_limit(56);
                ipv4.set_protocol(IpProtocol::Udp);
                match addr.ip() {
                    IpAddr::V4(ip) => ipv4.set_src_addr(ip.into()),
                    _ => panic!("Ipv6Addr is not supported"),
                }
                let src = ipv4.src_addr();
                let mut udp = UdpPacket::new_unchecked(ipv4.payload_mut());
                udp.set_dst_port(443);
                udp.set_src_port(addr.port());
                udp.set_len(8 + len as u16);

                // Forward non-first packets directly
                if let Some(domain) = connection_map.get(&addr) {
                    if let Some(server_ip) = resolution_record.get(domain) {
                        // The domain name is already resolved, forward directly.
                        info!("The domain name is already resolved, forward directly");
                        let dst = Ipv4Address::from_str(server_ip).unwrap();
                        udp.fill_checksum(&src.into(), &dst.into());
                        ipv4.set_dst_addr(dst);
                        ipv4.fill_checksum();
                        unsafe {
                            let mut sender_addr: sockaddr_ll = mem::zeroed();
                            let addr_ptr = mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sender_addr);
                            let len = sendto(raw_fd, eth.as_ref().as_ptr() as *mut c_void, eth.as_ref().len() as usize, 0,
                                                    addr_ptr as *mut sockaddr, 0);
                            info!("[{:?}] Forward {} bytes from {} to {}", start_ts.elapsed(), len, addr, server_ip);
                        }
                    } else {
                        // The domain name is not resovled yet, store to the forwarding map.
                        info!("The domain name is not resolved yet, store to the forwarding map");
                        let eths = forwarding_map.entry(domain.clone()).or_insert(Vec::new());
                        info!("Save {} bytes: {}", eth.as_ref().len(), domain);
                        eths.push((eth.as_ref().to_vec(), addr));
                    }
                // Send DNS query and wait for name resolution before forwarding
                } else {
                    info!("Send DNS query and wait for name resolution");
                    match parse_server_name(addr, &recv_buf.to_vec(), &mut config) {
                        Some(domain) => {
                            let eths = forwarding_map.entry(domain.clone()).or_insert(Vec::new());
                            eths.push((eth.as_ref().to_vec(), addr));
                            info!("Save {} bytes: {}", eth.as_ref().len(), domain);
                            dns_query(&domain, &dns_socket);
                        },
                        _ => { error!("Failed to parse/resolve the initial packet"); }
                    }
                }
            },
            _ => { }
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
                            if let Some(eths) = forwarding_map.get(&name) {
                                for (eth_buf, addr) in eths {
                                    connection_map.insert(*addr, name.clone());
                                    let mut eth = EthernetFrame::new_checked(eth_buf.clone()).unwrap();
                                    let mut ipv4 = Ipv4Packet::new_checked(eth.payload_mut()).unwrap();
                                    let src = ipv4.src_addr();
                                    let mut udp = UdpPacket::new_checked(ipv4.payload_mut()).unwrap();
                                    udp.fill_checksum(&src.into(), &ip.into());
                                    ipv4.set_dst_addr(ip.into());
                                    ipv4.fill_checksum();
                                    unsafe {
                                        let mut sender_addr: sockaddr_ll = mem::zeroed();
                                        let addr_ptr = mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sender_addr);
                                        let send_data = eth.as_ref();
                                        let len = sendto(raw_fd, send_data.as_ptr() as *mut c_void, send_data.len() as usize, 0,
                                                                addr_ptr as *mut sockaddr, 0);
                                        info!("[{:?}] Forward {} bytes from {} to {}", start_ts.elapsed(), len, addr, ip)
                                    }
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

fn main() -> Result<(), Box<dyn Error>> {
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();
    info!("Starting QUIC resolver");
    udp_server()?;
    Ok(())
}
