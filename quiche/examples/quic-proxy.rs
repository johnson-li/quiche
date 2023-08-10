#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::error::Error;
use std::net::{SocketAddr, UdpSocket, IpAddr};
use dns_parser::RData;
use env_logger::Builder;
use log::LevelFilter;
use quiche::Config;
use dns_parser::rdata::a::Record;

const MAX_DATAGRAM_SIZE: usize = 1350;

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

fn parse_server_name(from: SocketAddr, data: &Vec<u8>) -> Option<String> {
    let mut payload = data.clone();
    let hdr: quiche::Header<'_> = match quiche::Header::from_slice(&mut payload, quiche::MAX_CONN_ID_LEN) {
        Ok(v) => v,
        Err(_) => {
            error!("Failed to parse header");
            return None;
        }
    };
    let mut config: Config = init_quic_config();
    let scid = hdr.scid.clone();
    let mut conn = match quiche::accept(&scid, None, from, &mut config) {
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

type ConnectionMap = HashMap<u16, UdpSocket>;
type NameResolutionMap = HashMap<String, Vec<(u16, Vec<u8>)>>;

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

    let mut connection_records: ConnectionMap = HashMap::new();
    let mut resolution_records: NameResolutionMap = HashMap::new();
    let mut port_map: HashMap<u16, u16> = HashMap::new();  // server port -> client port
    let mut recv_buf: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];
    let mut client_addr: Option<IpAddr> = None;

    loop {
        // Step 1, read from the client
        match client_socket.recv_from(&mut recv_buf) {
            Ok((len, addr)) => {
                let data = recv_buf[..len].to_vec();
                if client_addr.is_none() || client_addr.unwrap() != addr.ip() {
                    info!("Update client address: {}", addr.ip());
                    client_addr = Some(addr.ip());
                }
                let server_socket: Option<&UdpSocket> = connection_records.get(&addr.port());
                if server_socket.is_some() {
                    // Forward non-initial packets directly to the server
                    server_socket.unwrap().send(&data).unwrap();
                } else {
                    // Perform DNS resolution for initial packets
                    match parse_server_name(addr, &data) {
                        Some(name) => {
                            dns_query(&name, &dns_socket);
                            if !resolution_records.contains_key(&name) {
                                resolution_records.insert(name.to_string(), Vec::new());
                            }
                            resolution_records.get_mut(&name).unwrap().push((addr.port(), data));
                        },
                        _ => { }
                    };
                }
            },
            _ => { }
        }

        // Step 2, read from the servers
        for (port, server_socket) in &connection_records {
            match server_socket.recv(&mut recv_buf) {
                Ok(len) => {
                    let target: SocketAddr = SocketAddr::new(client_addr.unwrap(), *port);
                    client_socket.send_to(&recv_buf[..len], &target)?;
                },
                _ => { }
            };
        }

        // Step 3, read from the DNS resolver and forward the initial packets
        match dns_socket.recv(&mut recv_buf) {
            Ok(len) => {
                let data = recv_buf[..len].to_vec();
                let response = dns_parser::Packet::parse(&data).unwrap();
                let name = response.questions[0].qname.to_string();
                for answer in response.answers {
                    match answer.data {
                        RData::A(Record(ip)) => {
                            info!("Create server socket {} for {}", ip, name);
                            let target: SocketAddr = SocketAddr::new(IpAddr::V4(ip), 443);
                            match resolution_records.remove(&name) {
                                Some(list) => {
                                    for (port, data) in list {
                                        let server_socket = UdpSocket::bind("0.0.0.0:0")?;
                                        server_socket.set_nonblocking(true)?;
                                        server_socket.connect(target)?;
                                        port_map.insert(server_socket.local_addr()?.port(), port);
                                        server_socket.send(&data)?;
                                        connection_records.insert(port, server_socket);
                                    }
                                },
                                _ => { }
                            };
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
    info!("Starting QUIC proxy");
    udp_server()?;
    Ok(())
}
