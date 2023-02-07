use std::net::UdpSocket;
use std::ops::Deref;


fn query(name: &str) {
    let start_ts = std::time::Instant::now();
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind to address");
    socket.connect("127.0.0.1:8053").expect("connect function failed");
    let mut query_data: Vec<u8> = b"\xdc\x5b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01".to_vec();
    let mut suffix = b"\x00\x00\x01\x00\x01\x00\x00\x29\x05\xac\x00\x00\x00\x00\x00\x00".to_vec();
    for s in name.split(".") {
        let mut v = [[s.len() as u8].as_ref(), s.as_bytes()].concat();
        query_data.append(v.as_mut());
    }
    query_data.append(suffix.as_mut());
    println!("{:?}", name.find(".").unwrap() as u8);
    socket.send(query_data.deref()).expect("couldn't send message");
    let mut recv_data = [0;1024];
    let (_, _) = socket.recv_from(&mut recv_data).unwrap();
    println!("DNS query takes {:?}", start_ts.elapsed());
}

fn main() {
    query("mobix.aeacus.xuebing.me")
}

