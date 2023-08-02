#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;
use env_logger::Builder;
use log::LevelFilter;
use quiche::Config;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, NameServerConfigGroup};


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

async fn resolve_host(host: &str, resolver: &TokioAsyncResolver) -> Result<String, String> {
    info!("Resolving {}", host);
    let response = resolver.lookup_ip(host).await.unwrap();
    for ip in response.iter() {
        return Ok(ip.to_string());
    }
    return Err(format!("Failed to resolve {}", host));
}

async fn forward_initial_request(data: Vec<u8>, server: &str, port: u16) -> Result<mio::net::UdpSocket, Box<dyn Error>> {
    let socket = std::net::UdpSocket::bind(format!("0.0.0.0:{}", port))?;
    let server_socket = mio::net::UdpSocket::from_socket(socket)?;
    let server_addr = server.parse()?;
    let addr = SocketAddr::new(server_addr, 443);
    server_socket.connect(addr)?;
    server_socket.send(&data)?;
    Ok(server_socket)
}

async fn forward_request(from: SocketAddr, data: Vec<u8>, server_socket: Option<&mio::net::UdpSocket>,
                         resolver: TokioAsyncResolver) -> Result<Option<mio::net::UdpSocket>, Box<dyn Error>> {
    if server_socket.is_some() {
        server_socket.unwrap().send(&data)?;
        return Ok(None);
    }
    let mut payload = data.clone();
    let hdr = quiche::Header::from_slice(&mut payload, quiche::MAX_CONN_ID_LEN)?;
    let mut config: Config = init_quic_config();
    let scid = hdr.scid.clone();
    let mut conn = quiche::accept(&scid, None, from, &mut config)?;
    let recv_info = quiche::RecvInfo { from };
    let _read = conn.recv_lite(payload.as_mut(), recv_info)?;
    let server_name = match conn.server_name() {
        Some(v) => v,
        None => {
            error!("Failed to get server name");
            return Ok(None);
        }
    };
    let dst_ip_str = resolve_host(server_name, &resolver).await?;
    let sock = forward_initial_request(data, &dst_ip_str, from.port()).await?;
    Ok(Some(sock))
}

async fn forward_response(data: Vec<u8>, client_socket: &mio::net::UdpSocket, target: SocketAddr) -> Result<(), Box<dyn Error>> {
    client_socket.send_to(&data, &target)?;
    Ok(())
}

type ConnectionMap = HashMap<u16, mio::net::UdpSocket>;

async fn udp_server() -> Result<(), Box<dyn Error>> {
    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let dns_server_ips: &[IpAddr] = &[IpAddr::V4(Ipv4Addr::new(127,0,0,1))];
    let name_servers = NameServerConfigGroup::from_ips_clear(dns_server_ips, 8053, true);
    let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers); 
    let resolver: TokioAsyncResolver = TokioAsyncResolver::tokio(resolver_config, Default::default())?;
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();
    let mut args = std::env::args();
    let cmd = &args.next().unwrap();
    if args.len() != 0 {
        info!("Usage: {}", cmd);
        info!("\nAn IP proxy serving as the Aeacus resolver.");
        error!("Invalid arguments");
        return Ok(());
    }
    let mut connection_records: ConnectionMap = HashMap::new();
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)), 443);
    let client_socket = mio::net::UdpSocket::bind(&listen_addr).unwrap();
    poll.register(
        &client_socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    ).unwrap();
    let mut recv_buf: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];
    let mut client_addr = None;

    loop {
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            let token = event.token();
            let port: u16 = token.0 as u16;
            let socket_to_read = match port {
                0 => &client_socket,
                _ => connection_records.get(&port).unwrap()
            };
            let (len, addr) = socket_to_read.recv_from(&mut recv_buf)?;
            info!("Received {} bytes from {}", len, addr);
            let start_ts = Instant::now();
            if port == 0 {
                if client_addr.is_none() {
                    client_addr = Some(addr.ip());
                }
                let udp_port = addr.port();
                let server_socket = connection_records.get(&udp_port);
                let server_socket = forward_request(addr, recv_buf[..len].to_vec(), server_socket, resolver.clone()).await?;
                if server_socket.is_some() {
                    let server_socket = server_socket.unwrap();
                    poll.register(&server_socket, mio::Token(udp_port as usize), 
                                  mio::Ready::readable(), mio::PollOpt::edge()).unwrap();
                    connection_records.insert(udp_port, server_socket);
                }
            } else {
                let target = SocketAddr::new(client_addr.unwrap(), port);
                forward_response(recv_buf[..len].to_vec(), &client_socket, target).await?;
            }
            info!("It takes {:?} to forward packet.", start_ts.elapsed());
        }
    }
}

#[tokio::main]
async fn main() {
    info!("Starting QUIC proxy");
    match udp_server().await {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to start QUIC proxy: {}", e);
        }
    }
}
