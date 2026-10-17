use crate::net::com::{ethernet, ipv4, udp};

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

    let udp = udp::Segment::new(src_sock_addr, dest_sock_addr, Vec::<u8>::try_from(&msg).unwrap()).unwrap();

    let ip = ipv4::Datagram::new(src_ip, dest_ip, udp).unwrap();

    let frame = ethernet::Frame::<ipv4::Datagram<udp::Segment>>::new(dest_mac_address, src_mac_address, ip);

    let recv_frame = ethernet::Frame::try_from(buffer).unwrap();

    let ip_payload = recv_frame.payload;

    let udp_paylod = ip_payload.payload;

    let dns_resp = udp_paylod.payload;

    if dns_resp.id == msg.id{
        // Parse mesage
    }



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
