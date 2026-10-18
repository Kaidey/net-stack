use crate::net::{com::{address::IPv4Address, ethernet, ipv4, udp}, resolve_domain_name};

mod crypto;
mod net;
mod os;

// TODO:
// Size validations for TCP, UDP Segments and Eth Frames
// Eth frame padding
// Replace pub struct properties with getter methods or analogous
// FIN retransmist for TCP Close and retransmits in genera
// IPv4 Fragmentation
// IPv4 and TCP Options
// TCP LIstener
// Handle dropping iptables rule on SIGINT. Currently only handled when TCP Connection is closed
// HTTP Client

fn main() {

    let name = "scanme.nmap.org";

    println!("Resolving Host Name '{}'\n", name);

    let res = resolve_domain_name(name).unwrap();
    let ip = IPv4Address::try_from(res.as_slice()).unwrap();

    println!("\nDNS Reply: {}", ip);


    // let new_conn = net::TcpConnection::new("45.33.32.156:80", None).unwrap();
    //
    // let http_payload = "GET / HTTP/1.1\r\nHost: scanme.nmap.org\r\nConnection: close\r\n\r\n"
    //     .to_string()
    //     .into_bytes();

    // new_conn.write(http_payload);
    // new_conn.read();

    // new_conn.close().unwrap();

    // os::drop_root_privilege();
}
