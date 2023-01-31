#[macro_use]
extern crate log;

use std::any::Any;
use std::borrow::BorrowMut;
use std::net;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use smoltcp::phy::wait as phy_wait;
use smoltcp::time::Instant;
use ring::rand::*;
use smoltcp::wire::{EthernetFrame, PrettyPrinter, Ipv4Packet, UdpPacket};
use std::os::unix::io::AsRawFd;
use quiche::h3::NameValue;
use env_logger::Builder;
use log::LevelFilter;
use smoltcp::phy::{Device, RawSocket, RxToken, Medium};
use smoltcp::wire::IpProtocol::Udp;
use quiche::ConnectionId;

const MAX_DATAGRAM_SIZE: usize = 1350;

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

fn main() {
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();
    let mut buf = [0; 65535];
    let mut args = std::env::args();
    let cmd = &args.next().unwrap();
    if args.len() != 0 {
        println!("Usage: {}", cmd);
        println!("\nSee tools/apps/ for more complete implementations.");
        return;
    }
    let mut socket = RawSocket::new("lo", Medium::Ethernet).unwrap();
    loop {
        phy_wait(socket.as_raw_fd(), None).unwrap();
        let (rx_token, _) = socket.receive().unwrap();
        rx_token.consume(Instant::now(), |buffer| {
            let mut ethernet = EthernetFrame::new_checked(buffer).unwrap();
            let mut ipv4 = Ipv4Packet::new_checked(ethernet.payload_mut()).unwrap();
            let mut src_data: [u8; 4] = ipv4.src_addr().0;
            let mut src = Ipv4Addr::from(src_data);
            if ipv4.protocol() == Udp {
                let mut udp = UdpPacket::new_checked(ipv4.payload_mut()).unwrap();
                let dst_port = udp.dst_port();
                let src_port = udp.src_port();
                let from = SocketAddr::new(IpAddr::V4(src), src_port);
                if dst_port == 4433 {
                    let mut payload = udp.payload_mut();
                    // println!(
                    //     "Got UDP packet {}",
                    //     PrettyPrinter::<Ipv4Packet<&[u8]>>::new("", &ipv4.into_inner())
                    // );
                    let hdr = quiche::Header::from_slice(
                        payload,
                        quiche::MAX_CONN_ID_LEN,
                    ).unwrap();
                    println!("Got packet {:?}", hdr);
                    let rng = SystemRandom::new();
                    let conn_id_seed =
                        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();
                    let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                    let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                    let conn_id: ConnectionId = conn_id.to_vec().into();
                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    scid.copy_from_slice(&conn_id);
                    let scid = ConnectionId::from_ref(&scid);
                    let token = hdr.token.as_ref().unwrap();
                    let odcid = validate_token(&from, token);
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
                    config.set_preferred_address(3281289190);
                    let mut conn =
                        quiche::accept(&scid, odcid.as_ref(), from, &mut config).unwrap();
                    let recv_info = quiche::RecvInfo { from };
                    let read = conn.recv(payload, recv_info).unwrap();
                    println!("{} processed {} bytes", conn.trace_id(), read);
                    println!("Target domain name: {}", conn.server_name().unwrap());
                }
            }
            Ok(())
        }).unwrap();
    }
}
