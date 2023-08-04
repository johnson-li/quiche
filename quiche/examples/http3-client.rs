#[macro_use]
extern crate log;

use std::{net::Ipv4Addr, time::Instant, collections::HashMap};

use ring::rand::*;
use env_logger::Builder;
use log::LevelFilter;
use dns_parser::rdata::a::Record;
use serde::{Deserialize, Serialize};


const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct DNSCacheItem {
    ttl: u32,
    ip: String,
    ts: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct DNSCache {
    cache: HashMap<String, DNSCacheItem>,
}

fn load_dns_cache() -> DNSCache {
    let cache_str = match std::fs::read_to_string("/tmp/dns_cache.json") {
        Ok(cache) => cache,
        Err(_) => String::new(),
    };
    let cache = serde_json::from_str(&cache_str)
        .unwrap_or(DNSCache {cache: HashMap::new()});
    cache
}

fn save_dns_cache(cache: DNSCache) {
    let cache_str = serde_json::to_string(&cache).unwrap();
    std::fs::write("/tmp/dns_cache.json", cache_str).unwrap();
}

fn get_current_ts() -> u64 {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    ts
}

fn name_resolution_from_cache(cache: &DNSCache, name: &String) -> Option<String> {
    let record = cache.cache.get(name)?;
    let ts = get_current_ts();
    if ts <= record.ts + record.ttl as u64 {
        info!("Use cached IP {} for {}, valid for {} s", 
            record.ip, name, record.ts + record.ttl as u64 - ts);
        return Some(record.ip.clone());
    }
    None
}

fn main() {
    let mut dns_cache = load_dns_cache();
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() < 1 {
        println!("Usage: {} url [server]", cmd);
        println!("\nHTTP3 Client.");
        return;
    }

    let url = url::Url::parse(&args.next().unwrap()).unwrap();
    let mut server_ip = match args.next() {
        Some(ip) => ip,
        None => String::new(),
    };
    let domain = url.domain().unwrap();
    if server_ip.is_empty() {
        server_ip = match name_resolution_from_cache(&dns_cache, &domain.to_string()) {
            Some(ip) => ip,
            None => server_ip,
        };
    }
    let mut dns_record : Option<DNSCacheItem> = None;
    if server_ip.is_empty() {
        let ts = Instant::now();
        let dns_socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        dns_socket.connect("195.148.127.234:8054").unwrap();
        let mut builder = dns_parser::Builder::new_query(0, false);
        builder.add_question(domain, false, dns_parser::QueryType::A, dns_parser::QueryClass::IN);
        let query = builder.build().unwrap();
        dns_socket.send(&query).unwrap();
        let buf = &mut [0; MAX_DATAGRAM_SIZE];
        let len = dns_socket.recv(buf).unwrap();
        let data = buf[..len].to_vec();
        let response = dns_parser::Packet::parse(&data).unwrap();
        for answer in response.answers {
            match answer.data {
                dns_parser::RData::A(Record(ip)) => {
                    server_ip = ip.to_string();
                    dns_record = Some(DNSCacheItem {
                        ttl: answer.ttl,
                        ip: server_ip.clone(),
                        ts: get_current_ts(),
                    });
                    break;
                },
                _ => { }
            }
        }
        info!("It takes {:?} to resolve {} to {}", ts.elapsed(), domain, server_ip);
    }
    if server_ip.is_empty() {
        error!("Unable to resolve {}", domain);
        return;
    }
    let exit_after_handshake = true;

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Resolve server address.
    let peer_ip: std::net::IpAddr = server_ip.parse().expect("Unable to parse IP address");
    let peer_addr = std::net::SocketAddr::new(peer_ip, 443);

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // *CAUTION*: this should not be set to `false` in production!!!
    config.verify_peer(false);

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

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

    let mut http3_conn = None;

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create a QUIC connection and initiate handshake.
    let mut conn =
        quiche::connect(url.domain(), &scid, peer_addr, &mut config).unwrap();

    info!(
        "connecting to {:} from {:} with scid {} (len: {})",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid),
        scid.len(),
    );

    let start_ts: std::time::Instant = std::time::Instant::now();
    let (write, send_info) = conn.send(&mut out).expect("initial send failed");

    info!("[{:?}] Send {} bytes to {:?}", start_ts.elapsed(), write, &send_info.to);
    while let Err(e) = socket.send_to(&out[..write], &send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            debug!("send() would block");
            continue;
        }

        panic!("send() failed: {:?}", e);
    }

    let h3_config = quiche::h3::Config::new().unwrap();

    // Prepare request.
    let mut path = String::from(url.path());

    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
        quiche::h3::Header::new(
            b":authority",
            url.host_str().unwrap().as_bytes(),
        ),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"quiche"),
    ];

    let mut req_sent = false;

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if events.is_empty() {
                debug!("timed out");

                conn.on_timeout();

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };
            info!("[{:?}] Recv {} bytes from {:?}", start_ts.elapsed(), len, &from);

            let recv_info = quiche::RecvInfo { from };

            // Process potentially coalesced packets.
            let _ = match conn.recv(&mut buf[..len], recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'read;
                },
            };

            let hdr = match quiche::Header::from_slice(
                buf.as_mut(),
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue 'read;
                },
            };

            info!("got packet {:?}", hdr);
        }

        debug!("done reading");

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }

        // Create a new HTTP/3 connection once the QUIC connection is established.
        if conn.is_established() && http3_conn.is_none() {
            info!(
                "[{}] handshake completed in {:?}",
                url, start_ts.elapsed()
            );
            if exit_after_handshake {
                info!("exit after handshake");
                break;
            }
            let server = Ipv4Addr::from(conn.get_preferred_address());
            info!(
                "migrate server to {}",
                server
            );
            conn.peer_addr = format!("{}:443", server).parse().expect("Fail to convert IP from str");
            http3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .unwrap(),
            );
        }

        // Send HTTP requests once the QUIC connection is established, and until
        // all requests have been sent.
        if let Some(h3_conn) = &mut http3_conn {
            if !req_sent {
                info!("sending HTTP request {:?}", req);

                h3_conn.send_request(&mut conn, &req, true).unwrap();

                req_sent = true;
            }
        }

        if let Some(http3_conn) = &mut http3_conn {
            // Process HTTP/3 events.
            loop {
                match http3_conn.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        info!(
                            "got response headers {:?} on stream id {}",
                            list, stream_id
                        );
                    },

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        while let Ok(read) =
                            http3_conn.recv_body(&mut conn, stream_id, &mut buf)
                        {
                            info!(
                                "got {} bytes of response data on stream {}",
                                read, stream_id
                            );

                            print!("{}", unsafe {
                                std::str::from_utf8_unchecked(&buf[..read])
                            });
                        }
                    },

                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        info!(
                            "response received in {:?}, closing...",
                            start_ts.elapsed()
                        );

                        conn.close(true, 0x00, b"kthxbye").unwrap();
                    },

                    Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                        error!(
                            "request was reset by peer with {}, closing...",
                            e
                        );

                        conn.close(true, 0x00, b"kthxbye").unwrap();
                    },

                    Ok((_flow_id, quiche::h3::Event::Datagram)) => (),

                    Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                        info!("GOAWAY id={}", goaway_id);
                    },

                    Err(quiche::h3::Error::Done) => {
                        break;
                    },

                    Err(e) => {
                        error!("HTTP/3 processing failed: {:?}", e);

                        break;
                    },
                }
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            info!("[{:?}] Send {} bytes to {:?}", start_ts.elapsed(), write, &send_info.to);
            if let Err(e) = socket.send_to(&out[..write], &send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break;
                }

                panic!("send() failed: {:?}", e);
            }
        }

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            break;
        }
    }
    if let Some(dns_record) = dns_record {
        dns_cache.cache.insert(domain.to_string(), dns_record);
        save_dns_cache(dns_cache);
    }
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();
    vec.join("")
}
