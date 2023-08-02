use std::collections::HashMap;
use pcap::{Device, Capture};
use argparse::{ArgumentParser, Store};
use smoltcp::wire::{EthernetFrame, Ipv4Packet, UdpPacket};
use quiche::{Config, Header};
use std::thread;
use std::net::{TcpStream, TcpListener, SocketAddr, IpAddr, Ipv4Addr};
use std::io::{Read, Write};
use std::sync::Arc;
use chashmap::CHashMap;
use quiche::Type::{Initial, Short};


fn handle_connection(mut stream: TcpStream) {
    let mut buf: [u8; 10] = [0; 10];
    let mut data: [u8; 10] = [1; 10];
    match stream.read(buf.as_mut_slice()) {
        Ok(size) => {
            println!("{}", size);
            if size != 10 {
                println!("Size wrong: {}", size);
                return;
            }
            stream.write_all(data.as_mut_slice()).unwrap();
            stream.flush().unwrap();
        }
        _ => return
    };
}

fn web_server(_map: Arc<CHashMap<ConnectionKey, u8>>) {
    let addr = "127.0.0.1:8087";
    println!("Listening on {}", addr);
    let listener = TcpListener::bind(addr).unwrap();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        handle_connection(stream);
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
struct ConnectionKey {
    pub client_port: u16,
    pub server_ip: String,
}


pub fn init_quic_config() -> Config {
    const MAX_DATAGRAM_SIZE: usize = 1350;
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

fn quic_monitor(map: Arc<CHashMap<ConnectionKey, u8>>) {
    let mut connections = HashMap::new();
    let mut config = init_quic_config();
    let mut nic = "lo".to_string();
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Monitor the QUIC traffic");
        ap.refer(&mut nic)
            .add_option(&["--nic"], Store,
                        "Name of the NIC");
        ap.parse_args_or_exit();
    }
    let dev_list = Device::list().unwrap();
    let mut dev_list = dev_list.into_iter().filter(|d| d.name == nic).collect::<Vec<Device>>();
    if dev_list.is_empty() {
        println!("NIC not found: {}", nic);
        return;
    }
    println!("Capturing {}", nic);
    let dev = dev_list.pop().unwrap();
    let mut cap = Capture::from_device(dev).unwrap()
        .promisc(true)
        .timeout(1)
        .snaplen(5000)
        .open().unwrap();

    let mut recv_buf: [u8; 10240] = [0; 10240];
    while let Ok(packet) = cap.next_packet() {
        recv_buf[..packet.len()].copy_from_slice(packet.data);
        let mut ethernet = EthernetFrame::new_checked(recv_buf).unwrap();
        let mut ipv4 = match Ipv4Packet::new_checked(ethernet.payload_mut()) {
            Ok(v) => v,
            _ => continue
        };
        let src_addr = ipv4.src_addr();
        let dst_addr = ipv4.dst_addr();
        let mut udp = match UdpPacket::new_checked(ipv4.payload_mut()) {
            Ok(v) => v,
            _ => continue
        };
        let src_port = udp.src_port();
        let dst_port = udp.dst_port();
        if dst_port != 4433 && src_port != 4433 &&
            dst_port != 443 && src_port != 443 {
            continue;
        }
        let mut payload = udp.payload_mut();
        let payload_len = payload.len();
        // println!("Received UDP packet of {} bytes", payload.len());

        loop {
            let quic_hdr = match Header::from_slice2(payload) {
                Ok(v) => v,
                Err(e) => {
                    println!("Failed to parse QUIC header: {}", e);
                    break;
                }
            };
            println!("[{}:{} > {}:{}] size={}, packet type={:?}, {:?}", src_addr, src_port,
                     dst_addr, dst_port, payload_len, quic_hdr.ty, quic_hdr);
            let conn_key = if src_port == 4433 || src_port == 443 {
                ConnectionKey {
                    client_port: dst_port,
                    server_ip: src_addr.to_string(),
                }
            } else {
                ConnectionKey {
                    client_port: src_port,
                    server_ip: dst_addr.to_string(),
                }
            };
            let mut state: u8 = if map.contains_key(&conn_key) {
                *map.get(&conn_key).unwrap()
            } else {
                0
            };
            let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src_addr)), src_port);
            let recv_info = quiche::RecvInfo { from };
            if state != 2 {
                if quic_hdr.ty == Initial {
                    state += 1;
                    map.insert(conn_key.clone(), state);
                    let scid = quic_hdr.scid.clone();
                    let mut conn = quiche::accept(&scid, None, from, &mut config).unwrap();
                    let read = match conn.recv_lite(payload, recv_info) {
                        Ok(v) => v,
                        Err(e) => {
                            println!("{}", e);
                            0
                        }
                    };
                    connections.insert(conn_key.clone(), conn);
                    println!("QUIC read {} bytes", read);
                    if read > 0 {
                        payload = payload[read..].as_mut();
                        continue
                    }
                }
            } else if state == 1 && (src_port == 443 || src_port == 4433) {

            }
            if quic_hdr.ty == Short {
                if *map.get(&conn_key).unwrap() != 2 {
                    map.insert(conn_key.clone(), 2);
                    println!("Handshake finished: {:?}", conn_key);
                }
            }
            break
        }
    }
}

fn main() {
    // let map: HashMap<u8, u8> = HashMap::new();
    let map: CHashMap<ConnectionKey, u8> = CHashMap::new();
    let map = Arc::new(map);
    let m1 = map.clone();
    let handle1 = thread::spawn(move || {
        quic_monitor(m1);
    });
    let m2 = map.clone();
    let handle2 = thread::spawn(move || {
        web_server(m2);
    });
    handle1.join().unwrap();
    handle2.join().unwrap();
}