#[macro_use]
extern crate log;
extern crate clap;

use clap::Parser;
use url::Url;
use std::{net::{Ipv4Addr, SocketAddr}, time::Instant, collections::HashMap};
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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct MyArgs {
    #[arg(short, long)]
    ip_proxy: Option<String>,
    #[arg(short, long)]
    ldns: Option<String>,
    #[arg(short, long)]
    url: String,
    #[arg(short, long)]
    aeacus_proxy: Option<String>,
    #[arg(short, long)]
    zero_rtt: bool,
}

fn main() {
    let args = MyArgs::parse();
    info!("args: {:?}", args);
    let mut dns_cache = load_dns_cache();
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let url = Url::parse(args.url.as_str()).unwrap();
    let aeacus_proxy = args.aeacus_proxy;
    let ip_proxy = args.ip_proxy;
    let zero_rtt = args.zero_rtt;
    let ldns = args.ldns;
    let session_file = "/tmp/http3-client-session.bin";
    let mut sessions: Option<HashMap<String, Vec<u8>>> = if zero_rtt {
        match std::fs::metadata(session_file) {
            Ok(_) => {
                let data = std::fs::read(session_file).unwrap();
                let sessions: HashMap<String, Vec<u8>> = bincode::deserialize(&data).unwrap();
                Some(sessions)
            }
            Err(_) => Some(HashMap::new())
        } 
    } else {
        None
    };
    let domain = url.domain().unwrap();
    let mut dns_record : Option<DNSCacheItem> = None;

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
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
    config.enable_early_data();

    let start_ts = Instant::now();
    // If Aeacus proxy is in use, there is no need to perform name resolution
    // Resolve the domain name if Aeacus proxy is not in use
    let mut server_ip = None;
    if aeacus_proxy.is_none() {
        server_ip =  name_resolution_from_cache(&dns_cache, &domain.to_string());
        if server_ip.is_none() {
            let dns_socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
            dns_socket.connect(ldns.unwrap()).unwrap();
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
                        server_ip = Some(ip.to_string());
                        dns_record = Some(DNSCacheItem {
                            ttl: answer.ttl,
                            ip: server_ip.clone().unwrap(),
                            ts: get_current_ts(),
                        });
                        break;
                    },
                    _ => { }
                }
            }
            info!("It takes {:?} to resolve {} to {}", start_ts.elapsed(), domain, server_ip.clone().unwrap());
        }
        if server_ip.is_none() {
            error!("Unable to resolve {}", domain);
            return;
        }
    }
    let exit_after_handshake = false;

    // Setup the event loop.
    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Remote peer is 
    // 1. quic-proxy if aeacus proxy specified
    // 2. ip-proxy if ip proxy specified
    // 3. server otherwise
    let peer_addr = if ip_proxy.is_some() {
        SocketAddr::new(ip_proxy.clone().unwrap().parse().unwrap(), 8443)
    } else if aeacus_proxy.is_some() {
        SocketAddr::new(aeacus_proxy.clone().unwrap().parse().unwrap(), 443)
    } else {
        SocketAddr::new(server_ip.clone().unwrap().parse().unwrap(), 443)
    };

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

    let mut http3_conn = None;
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);
    let mut conn =
        quiche::connect(url.domain(), &scid, peer_addr, &mut config).unwrap();
    if let Some(sessions) = &mut sessions {
        if let Some(session) = sessions.get_mut(domain) {
            info!("Resuming session for {}", domain);
            conn.set_session(&session).unwrap();
        }
    }
    let dsid = conn.destination_id();
    info!(
        "connecting to {:} from {:} with scid {} (len: {}), dsid {} (len: {})",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid),
        scid.len(),
        hex_dump(&dsid),
        dsid.len(),
    );

    let (mut write, send_info) = if ip_proxy.is_some() {
        let ip: Ipv4Addr = server_ip.clone().unwrap().parse().unwrap();
        out[..4].copy_from_slice(ip.octets().as_ref());
        conn.send(&mut out[4..]).expect("initial send failed")
    } else {
        conn.send(&mut out).expect("initial send failed")
    };
    let mut path = String::from(url.path());
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
    if ip_proxy.is_some() {
        write += 4;
    }
    info!("[{:?}] Send {} bytes to {:?}", start_ts.elapsed(), write, &send_info.to);
    while let Err(e) = socket.send_to(&out[..write], &send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            debug!("send() would block");
            continue;
        }
        panic!("send() failed: {:?}", e);
    }

    let mut req_sent = false;
    info!("[{:?}] Early data: {:?}", start_ts.elapsed(), conn.is_in_early_data());
    if conn.is_in_early_data() && http3_conn.is_none() {
        let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &quiche::h3::Config::new().unwrap()).unwrap();
        info!("[{:?}] Sending HTTP request", start_ts.elapsed());
        h3_conn.send_request(&mut conn, &req, true).unwrap();
        req_sent = true;
        http3_conn = Some(h3_conn);
        // Send 0-RTT data
        let (mut write, send_info) = if ip_proxy.is_some() {
            let ip: Ipv4Addr = server_ip.clone().unwrap().parse().unwrap();
            out[..4].copy_from_slice(ip.octets().as_ref());
            conn.send(&mut out[4..]).expect("0-RTT send failed")
        } else {
            conn.send(&mut out).expect("0-RTT send failed")
        };
        if ip_proxy.is_some() {
            write += 4;
        }
        info!("[{:?}] Send {} bytes to {:?}", start_ts.elapsed(), write, &send_info.to);
        while let Err(e) = socket.send_to(&out[..write], &send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("send() would block");
                continue;
            }
            panic!("send() failed: {:?}", e);
        }
    }

    let h3_config = quiche::h3::Config::new().unwrap();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    loop {
        poll.poll(&mut events, conn.timeout()).unwrap();

        'read: loop {
            if events.is_empty() {
                debug!("timed out");
                conn.on_timeout();
                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }
                    panic!("recv() failed: {:?}", e);
                },
            };
            info!("[{:?}] Recv {} bytes from {:?}", start_ts.elapsed(), len, &from);
            let recv_info = quiche::RecvInfo { from };
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

        if conn.is_closed() {
            info!("connection closed, {:?}", conn.stats());
            if let Some(sessions) = &mut sessions {
                if let Some(session) = conn.session() {
                    sessions.insert(domain.to_string(), session);
                    let data = bincode::serialize(sessions).unwrap();
                    std::fs::write(session_file, data).unwrap();
                    info!("Save session to {}", session_file);
                } else {
                    info!("No session");
                }
            }
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
                conn.close(false, 0x1, b"finish").ok();
            }
            if aeacus_proxy.is_some() {
                let server = Ipv4Addr::from(conn.get_preferred_address());
                info!("migrate server to {}", server);
                conn.peer_addr = format!("{}:443", server).parse().expect("Fail to convert IP from str");
            }
            http3_conn = Some(
                quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .unwrap(),
            );
        }

        // Send HTTP requests once the QUIC connection is established, and until
        // all requests have been sent.
        if let Some(h3_conn) = &mut http3_conn {
            if !req_sent {
                info!("[{:?}] Sending HTTP request {:?}", start_ts.elapsed(), req);

                h3_conn.send_request(&mut conn, &req, true).unwrap();

                req_sent = true;
            }
        }

        if let Some(http3_conn) = &mut http3_conn {
            loop {
                match http3_conn.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        info!(
                            "[{:?}] got response headers {:?} on stream id {}",
                            start_ts.elapsed(), list[0], stream_id
                        );
                    },

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        while let Ok(read) =
                            http3_conn.recv_body(&mut conn, stream_id, &mut buf)
                        {
                            info!(
                                "[{:?}] got {} bytes of response data on stream {}",
                                start_ts.elapsed(), read, stream_id
                            );
                            // print!("{}", unsafe {
                            //     std::str::from_utf8_unchecked(&buf[..read])
                            // });
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
            let mut buf: &mut[u8] = out.as_mut();
            if ip_proxy.is_some() {
                let ip: Ipv4Addr = server_ip.clone().unwrap().parse().unwrap();
                out[..4].copy_from_slice(ip.octets().as_ref());
                buf = out[4..].as_mut();
            }
            let (mut write, send_info) = match conn.send(buf) {
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
            if ip_proxy.is_some() {
                write += 4;
            }
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
            if let Some(sessions) = &mut sessions {
                if let Some(session) = conn.session() {
                    sessions.insert(domain.to_string(), session);
                    let data = bincode::serialize(sessions).unwrap();
                    std::fs::write(session_file, data).unwrap();
                    info!("Save session to {}", session_file);
                } else {
                    info!("No session");
                }
            }
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
