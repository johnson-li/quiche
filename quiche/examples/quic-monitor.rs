use std::collections::HashMap;
use pcap::{Device, Capture};
use argparse::{ArgumentParser, Store};
use smoltcp::wire::{EthernetFrame, Ipv4Packet, UdpPacket};
use quiche::{ConnectionId, Header};
use std::thread;
use std::net::{TcpStream, TcpListener};
use std::io::{Read, Write};
use std::sync::Arc;
use chashmap::CHashMap;
use quiche::Type::{Handshake, Initial};

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

fn web_server(map: Arc<CHashMap<ConnectionId, u8>>) {
    let addr = "127.0.0.1:8087";
    println!("Listening on {}", addr);
    let listener = TcpListener::bind(addr).unwrap();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        handle_connection(stream);
    }
}


fn quic_monitor(map: Arc<CHashMap<ConnectionId, u8>>) {
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
    println!("Capturing {nic}");
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
        let payload = udp.payload_mut();
        let payload_len = payload.len();
        // println!("Received UDP packet of {} bytes", payload.len());
        let quic_hdr = match Header::from_slice(payload, 8) {
            Ok(v) => v,
            _ => continue
        };
        println!("[{}:{} => {}:{}] size={}, packet type={:?}, {:?}", src_addr, src_port,
                 dst_addr, dst_port, payload_len, quic_hdr.ty, quic_hdr);
        let conn_id = if src_port == 4433 || src_port == 443 {
            quic_hdr.dcid
        } else {
            quic_hdr.scid
        };
        // let mut map: HashMap<ConnectionId, u8> = HashMap::new();
        let mut state: u8 = if map.contains_key(&conn_id) {
            *map.get(&conn_id).unwrap()
        } else {
            0
        };
        if state == 0 && (dst_port == 443 || dst_port == 4433) {
            if payload_len >= 1200 && quic_hdr.ty == Initial {
                state += 1;
                map.insert(conn_id.clone(), state);
            }
        } else if state == 1 && (src_port == 443 || src_port == 4433) {
            if payload_len >= 500 && quic_hdr.ty == Initial {
                state += 1;
                map.insert(conn_id.clone(), state);
            } else if payload_len <= 200 && quic_hdr.ty == Initial {
                state = 255;
                map.insert(conn_id.clone(), state);
            }
        } else if state == 2 && (dst_port == 443 || dst_port == 4433) {
            if payload_len >= 300 && quic_hdr.ty == Initial {
                state += 1;
                map.insert(conn_id.clone(), state);
            } else if payload_len >= 300 && quic_hdr.ty == Handshake {
                state += 1;
                map.insert(conn_id.clone(), state);
            } else if payload_len <= 120 && quic_hdr.ty == Handshake {
                state = 255;
                map.insert(conn_id.clone(), state);
            }
        }
        if map.contains_key(&conn_id) {
            println!("Update {:?} to {}", conn_id, *map.get(&conn_id).unwrap());
        }
    }
}

fn main() {
    // let map: HashMap<u8, u8> = HashMap::new();
    let map: CHashMap<ConnectionId, u8> = CHashMap::new();
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