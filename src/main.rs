mod crypto;
mod net;
mod os;

// TODO:
// Impl something similar to to_sock_addr (traits) in order to isolate address convertion logic
// Impl ephemeral ports if no source port is supplied for TcpConnection
// Replace pub struct properties with getter methods or analogous
// FIN retransmist for TCP Close and retransmits in genera
// DSN Resolution
// IPv4 Fragmentation
// IPv4 and TCP Options
// TCP LIstener
// Handle dropping iptables rule on SIGINT. Currently only handled when TCP Connection is closed

fn main() {
    

    let new_conn = net::TcpConnection::new("45.33.32.156:80", None).unwrap();

    let http_payload = "GET / HTTP/1.1\r\nHost: scanme.nmap.org\r\nConnection: close\r\n\r\n"
        .to_string()
        .into_bytes();

    // new_conn.write(http_payload);
    // new_conn.read();

    new_conn.close().unwrap();

    // os::drop_root_privilege();
}
