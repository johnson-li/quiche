#[macro_use] 
extern crate log;

use env_logger::Builder;
use log::LevelFilter;
use std::mem;
use smoltcp::wire::{EthernetFrame, Ipv4Packet, UdpPacket, EthernetProtocol, IpProtocol};
use quiche::Config;
use std::net::UdpSocket;
use quiche::Type::{Initial, Short};
use libc::{socket, recvfrom, PF_PACKET, SOCK_RAW, SOCK_NONBLOCK, c_void, sockaddr_ll, sockaddr, setsockopt, SOL_SOCKET, SO_BINDTODEVICE, socklen_t};

const MAX_DATAGRAM_SIZE: usize = 1350;
const ETH_TYPE: u16 = 0x0800;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
struct ConnectionKey {
    pub client_port: u16,
    pub server_ip: String,
}


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

fn quic_monitor() {
    // let mut connections = HashMap::new();
    let nic = "br0".to_string();
    info!("Capturing {}", nic);
    let sock_quic_resolver = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock_quic_resolver.set_nonblocking(true).unwrap();
    sock_quic_resolver.connect("192.168.57.12:8080").unwrap();
    let raw_fd = unsafe {
        let fd = socket(PF_PACKET, SOCK_RAW|SOCK_NONBLOCK, ETH_TYPE.to_be() as i32);
        let res = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, nic.as_ptr() as *const c_void, 3);
        info!("Bind NIC res: {}", res);
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
            packet_size = recvfrom(raw_fd, recv_buf.as_mut_ptr() as *mut c_void, recv_buf.len(), 0,
                                   addr_ptr as *mut sockaddr, &mut addr_buf_sz);
        }
        if packet_size <= 0 {
            continue;
        }
        let mut eth = EthernetFrame::new_checked(recv_buf.clone()).unwrap();
        if eth.ethertype() == EthernetProtocol::Ipv4 {
            let mut ipv4 = match Ipv4Packet::new_checked(eth.payload_mut()) {
                Ok(v) => v,
                _ => continue,
            };
            let src = ipv4.src_addr();
            // let dst = ipv4.dst_addr();
            if ipv4.protocol() == IpProtocol::Udp {
                let mut udp = UdpPacket::new_unchecked(ipv4.payload_mut());
                if udp.dst_port() == 443 || udp.src_port() == 443 {
                    info!("Detected {} bytes from {:?}", packet_size, src);
                    let hdr: quiche::Header<'_> = match quiche::Header::from_slice(&mut udp.payload_mut(), quiche::MAX_CONN_ID_LEN) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let port = if udp.dst_port() == 443 {
                        udp.src_port()
                    } else {
                        udp.dst_port()
                    };
                    if hdr.ty == Short {
                        // Short header indicates successful handshake
                        let mut buf: [u8; 10] = [0; 10];
                        buf[0] = 1;
                        buf[1] = ((port >> 8) & 0xff) as u8;
                        buf[2] = (port & 0xff) as u8;
                        info!("Notify resolver of successful handshake, port: {}", port);
                        sock_quic_resolver.send(buf.as_ref()).unwrap();
                    } else if hdr.ty == Initial {

                    }
                }
            }
        }
    }
}

fn main() {
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();
    quic_monitor();
}