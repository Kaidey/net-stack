mod com;
mod socket;

use com::ethernet_payloads::{arp, ipv4};

use crate::net::com::{FrameType, run_arp};

pub fn test() {
    // let sock_fd = socket::new_socket(Some("eth1"));

    // let dest_mac: Option<[u8; 6]> = run_arp(
    //     sock_fd,
    //     [0x94, 0xBB, 0x43, 0x4E, 0xCE, 0xBC],
    //     [192, 168, 68, 101],
    //     [192, 168, 68, 100],
    // );
    //
    // println!("Destination MAC: {:02X?}", dest_mac.unwrap());
    //
    let packet: ipv4::Datagram = ipv4::Datagram::new(
        ipv4::Protocol::ICMP,
        [192, 168, 68, 1],
        [192, 172, 50, 1],
        vec![1, 2],
    )
    .ttl(128)
    .flags(ipv4::FragmentationFlags::FragMore)
    .fragment_offset(0xB1)
    .opts(vec![9,8,2,5,5,4])
    .tos(ipv4::dscp::DEFAULT_FORWARDING);

    println!("{}", packet);

}
