#[macro_use]
extern crate log;

use std::borrow::Borrow;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use smoltcp::phy::{TxToken, wait as phy_wait};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetFrame, IpAddress, Ipv4Address, Ipv4Packet, UdpPacket};
use std::os::unix::io::AsRawFd;
use env_logger::Builder;
use log::LevelFilter;
use smoltcp::phy::{Device, RawSocket, RxToken, Medium};
use smoltcp::wire::IpProtocol::Udp;
use std::net::UdpSocket;
use std::ops::Deref;

const MAX_DATAGRAM_SIZE: usize = 1350;
const IFACE: &str = "br0";

fn dns_query(name: &str, socket: &UdpSocket) {
    let mut query_data: Vec<u8> = b"\xdc\x5b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01".to_vec();
    let mut suffix = b"\x00\x00\x01\x00\x01\x00\x00\x29\x05\xac\x00\x00\x00\x00\x00\x00".to_vec();
    for s in name.split(".") {
        let mut v = [[s.len() as u8].as_ref(), s.as_bytes()].concat();
        query_data.append(v.as_mut());
    }
    query_data.append(suffix.as_mut());
    socket.send(query_data.deref()).expect("couldn't send message");
    let mut recv_data = [0; 1024];
    let (_, _) = socket.recv_from(&mut recv_data).unwrap();
}

fn main() {
    let dns_socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind to address");
    // socket.connect("127.0.0.1:8053").expect("connect function failed");
    dns_socket.connect("127.0.0.53:53").expect("connect function failed");
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
    let mut socket = RawSocket::new(IFACE, Medium::Ethernet).unwrap();
    loop {
        phy_wait(socket.as_raw_fd(), None).unwrap();
        let (rx_token, tx_token) = socket.receive().unwrap();
        rx_token.consume(Instant::now(), |buffer| {
            let mut buffer_egress = vec![0; buffer.len()];
            buffer_egress.clone_from_slice(buffer);
            let packet_size = buffer.len();
            let mut ethernet = EthernetFrame::new_checked(buffer).unwrap();
            let mut ipv4 = Ipv4Packet::new_checked(ethernet.payload_mut()).unwrap();
            let src_data: [u8; 4] = ipv4.src_addr().0;
            let dst_data: [u8; 4] = ipv4.dst_addr().0;
            let src = Ipv4Addr::from(src_data);
            let dst = Ipv4Addr::from(dst_data);
            if ipv4.protocol() == Udp {
                let mut udp = UdpPacket::new_checked(ipv4.payload_mut()).unwrap();
                let dst_port = udp.dst_port();
                let src_port = udp.src_port();
                let from = SocketAddr::new(IpAddr::V4(src), src_port);
                let host_ip: Ipv4Addr = "192.168.58.13".parse().unwrap();
                if dst_port == 4433 && dst == host_ip {
                    let payload = udp.payload_mut();
                    let hdr = match quiche::Header::from_slice(
                        payload,
                        quiche::MAX_CONN_ID_LEN,
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Parsing packet header failed: {:?}", e);
                            return Ok(());
                        }
                    };
                    info!("Got packet {:?}", hdr);
                    let start_ts = std::time::Instant::now();
                    let scid = hdr.scid.clone();
                    let mut conn =
                        quiche::accept(&scid, None, from, &mut config).unwrap();
                    let recv_info = quiche::RecvInfo { from };
                    let read = match conn.recv_lite(payload, recv_info) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Parsing packet failed: {:?}", e);
                            return Ok(());
                        }
                    };
                    info!("It takes {:?} to parse the packet", start_ts.elapsed());
                    info!("{} processed {} bytes", conn.trace_id(), read);
                    // dns_query(conn.server_name().unwrap(), &dns_socket);
                    info!("It takes {:?} to finish DNS query", start_ts.elapsed());
                    let dst_ip_str = "195.148.127.230";
                    info!("Target domain name: {}, forwarding to {}", conn.server_name().unwrap(), dst_ip_str);
                    let dst_ip: Ipv4Addr = dst_ip_str.parse().unwrap();
                    let dst = Ipv4Address::from_bytes(dst_ip.octets().as_slice());
                    tx_token.consume(Instant::now(), packet_size, |send_buffer| {
                        let mut ethernet = EthernetFrame::new_checked(buffer_egress).unwrap();
                        let mut ipv4 = Ipv4Packet::new_checked(ethernet.payload_mut()).unwrap();
                        ipv4.set_dst_addr(dst);
                        let mut udp = UdpPacket::new_checked(ipv4.payload_mut()).unwrap();
                        udp.fill_checksum(IpAddress::from(src).borrow(), IpAddress::from(dst).borrow());
                        ipv4.fill_checksum();
                        send_buffer.clone_from_slice(ethernet.as_ref());
                        info!("It takes {:?} to forward the packet", start_ts.elapsed());
                        Ok(())
                    }).unwrap();
                }
            }
            Ok(())
        }).unwrap();
    }
}
