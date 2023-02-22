#[macro_use]
extern crate log;

use std::borrow::Borrow;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use smoltcp::wire::{EthernetFrame, IpAddress, Ipv4Address, Ipv4Packet, UdpPacket};
use env_logger::Builder;
use log::LevelFilter;
use smoltcp::wire::IpProtocol::Udp;
use std::net::UdpSocket;
use std::ops::Deref;
use libc::{socket, PF_PACKET, SOCK_RAW, recvfrom, c_void, sockaddr_ll, sockaddr, socklen_t, sendto, setsockopt, SOL_SOCKET, SO_BINDTODEVICE};
use quiche::Config;


const MAX_DATAGRAM_SIZE: usize = 1350;
const ETH_TYPE: u16 = 0x0800;

fn dns_query(name: &str, socket: &UdpSocket) {
    let mut query_data: Vec<u8> = b"\xdc\x5b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01".to_vec();
    let mut suffix = b"\x00\x00\x01\x00\x01\x00\x00\x29\x05\xac\x00\x00\x00\x00\x00\x00".to_vec();
    for s in name.split(".") {
        let mut v = [[s.len() as u8].as_ref(), s.as_bytes()].concat();
        query_data.append(v.as_mut());
    }
    query_data.append(suffix.as_mut());
    socket.send(query_data.deref()).expect("couldn't send message");
    let mut recv_data = [0; 10240];
    let (_, _) = socket.recv_from(&mut recv_data).unwrap();
}

fn init_quic_config() -> Config {
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

fn main() {
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();
    let mut args = std::env::args();
    let cmd = &args.next().unwrap();
    if args.len() != 0 {
        info!("Usage: {}", cmd);
        info!("\nSee tools/apps/ for more complete implementations.");
        return;
    }
    let mut config = init_quic_config();
    let fd = unsafe {
        let fd = socket(PF_PACKET, SOCK_RAW, ETH_TYPE.to_be() as i32);
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "br0".as_ptr() as *const c_void, 3);
        fd
    };
    let mut recv_buf: [u8; 10240] = [0; 10240];
    let mut sender_addr: sockaddr_ll = unsafe { mem::zeroed() };
    let mut addr_buf_sz: socklen_t = mem::size_of::<sockaddr_ll>() as socklen_t;
    let mut addr_ptr: *mut sockaddr;
    let mut packet_size: isize;
    loop {
        unsafe {
            addr_ptr = mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sender_addr);
            packet_size = recvfrom(fd, recv_buf.as_mut_ptr() as *mut c_void, recv_buf.len(), 0,
                                   addr_ptr as *mut sockaddr, &mut addr_buf_sz);
        }
        // println!("Received data of {}", len);
        let recv_buf_clone = recv_buf.clone();
        let mut ethernet = EthernetFrame::new_checked(recv_buf).unwrap();
        let mut ipv4 = match Ipv4Packet::new_checked(ethernet.payload_mut()) {
            Ok(v) => v,
            _ => continue
        };
        let src_data: [u8; 4] = ipv4.src_addr().0;
        let dst_data: [u8; 4] = ipv4.dst_addr().0;
        let src = Ipv4Addr::from(src_data);
        let dst = Ipv4Addr::from(dst_data);
        if ipv4.protocol() == Udp {
            let mut udp = match UdpPacket::new_checked(ipv4.payload_mut()) {
                Ok(v) => v,
                _ => continue
            };
            let dst_port = udp.dst_port();
            let src_port = udp.src_port();
            let from = SocketAddr::new(IpAddr::V4(src), src_port);
            let host_ip: Ipv4Addr = "192.168.58.13".parse().unwrap();
            // let host_ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
            if dst_port == 4433 && dst == host_ip {
                let payload = udp.payload_mut();
                info!("Payload size: {}", payload.len());
                let hdr = match quiche::Header::from_slice(
                    payload,
                    quiche::MAX_CONN_ID_LEN,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Parsing packet header failed: {}", e);
                        continue;
                    }
                };
                // info!("Got packet {:?}", hdr);
                let start_ts = std::time::Instant::now();
                let scid = hdr.scid.clone();
                let mut conn =
                    quiche::accept(&scid, None, from, &mut config).unwrap();
                let recv_info = quiche::RecvInfo { from };
                let read = match conn.recv_lite(payload, recv_info) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Parsing packet failed: {}", e);
                        continue;
                    }
                };
                info!("It takes {} ms to parse the packet", start_ts.elapsed().as_millis());
                info!("{} processed {} bytes", conn.trace_id(), read);
                // dns_query(conn.server_name().unwrap(), &dns_socket);
                info!("It takes {} ms to finish DNS query", start_ts.elapsed().as_millis());
                let dst_ip_str = "195.148.127.230";
                let server_name = match conn.server_name() {
                    Some(v) => v,
                    _ => continue
                };
                info!("Target domain name: {}, forwarding to {}", server_name, dst_ip_str);
                let dst_ip: Ipv4Addr = dst_ip_str.parse().unwrap();
                let dst = Ipv4Address::from_bytes(dst_ip.octets().as_slice());
                let mut ethernet = EthernetFrame::new_checked(recv_buf_clone).unwrap();
                let mut ipv4 = Ipv4Packet::new_checked(ethernet.payload_mut()).unwrap();
                let mut udp = UdpPacket::new_checked(ipv4.payload_mut()).unwrap();
                udp.fill_checksum(IpAddress::from(src).borrow(), IpAddress::from(dst).borrow());
                ipv4.set_dst_addr(dst);
                ipv4.fill_checksum();
                let send_data = ethernet.as_ref();
                unsafe {
                    // let addr_ptr = mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(&mut sender_addr);
                    let len = sendto(fd, send_data.as_ptr() as *mut c_void, packet_size as usize, 0,
                                     addr_ptr as *mut sockaddr, addr_buf_sz);
                    info!("It takes {} ms to forward the packet, size: {} bytes", start_ts.elapsed().as_millis(), len);
                }
            }
        }
    }
}
