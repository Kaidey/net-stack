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
    let msg = net::com::dns::Message::new("www.google.com").unwrap();
    println!("Message: \n{}", msg);
    let m_bytes = Vec::<u8>::try_from(&msg).unwrap();
    println!("Message as bytes: {:02X?}", m_bytes);
    println!("From bytes:\n{}", net::com::dns::Message::try_from(m_bytes.as_slice()).unwrap());

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
