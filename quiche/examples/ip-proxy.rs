#[macro_use]
extern crate log;

use std::{error::Error, net::{UdpSocket, IpAddr, SocketAddr}, collections::HashMap};
use env_logger::Builder;
use log::LevelFilter;

const MAX_DATAGRAM_SIZE: usize = 1350;

fn udp_server() -> Result<(), Box<dyn Error>> {
    let client_socket = UdpSocket::bind("0.0.0.0:8443")?;
    client_socket.set_nonblocking(true)?;
    let mut recv_buf: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];
    // let mut port_map: HashMap<u16, u16> = HashMap::new();  // Server port -> client port
    let mut connection_records: HashMap<u16, UdpSocket> = HashMap::new();
    let mut client_addr: Option<IpAddr> = None;

    loop {
        // Step 1, read from the client
        match client_socket.recv_from(&mut recv_buf) {
            Ok((len, addr)) => {
                if client_addr.is_none() || client_addr.unwrap() != addr.ip() {
                    info!("Update client address: {}", addr.ip());
                    client_addr = Some(addr.ip());
                }
                let port = addr.port();
                let mut server_ip: [u8; 4] = [0; 4];
                server_ip.copy_from_slice(&recv_buf[..4]);
                let server_addr = IpAddr::V4(server_ip.into());
                let quic_payload = &recv_buf[4..];
                match connection_records.get(&port) {
                    Some(socket) => {
                        socket.send(&recv_buf[..len])?;
                    }
                    None => {
                        let server_socket = UdpSocket::bind("0.0.0.0:0")?;
                        server_socket.set_nonblocking(true)?;
                        server_socket.connect(SocketAddr::new(server_addr, 443))?;
                        server_socket.send(quic_payload)?;
                        connection_records.insert(port, server_socket);
                    }
                }
            }
            _ => {}
        }

        // Step 2, read from the server
        for (port, server_socket) in &connection_records {
            match server_socket.recv(&mut recv_buf) {
                Ok(len) => {
                    let target = SocketAddr::new(client_addr.unwrap(), *port);
                    client_socket.send_to(&recv_buf[..len], &target)?;
                }
                _ => {}
            }
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();
    info!("Starting IP proxy");
    udp_server()?;
    Ok(())
}
