mod com;
mod socket;

use crate::crypto;
use crate::net::com::{FrameType, ethernet_payloads::tcp, run_arp};
use com::ethernet_payloads::{arp, ipv4, utils};

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

    let tcp: tcp::Segment = tcp::Segment::new(
        &[192 as u8, 168 as u8, 68 as u8, 1 as u8],
        1,
        &[192 as u8, 172 as u8, 50 as u8, 1 as u8],
        2,
        tcp::Flags::SYN,
        vec![1, 2],
    )
    .checksum(
        &[192 as u8, 168 as u8, 68 as u8, 1 as u8],
        &[192 as u8, 172 as u8, 50 as u8, 1 as u8],
        ipv4::Protocol::TCP.bits(),
    );

    let packet: ipv4::Datagram = ipv4::Datagram::new(
        ipv4::Protocol::TCP,
        [192, 168, 68, 1],
        [192, 172, 50, 1],
        Vec::from(&tcp),
    )
    .unwrap()
    .ttl(128)
    .flags(ipv4::FragmentationFlags::MORE_FRAGMENTS)
    .fragment_offset(0xB1)
    .dscp(ipv4::Dscp::AF21)
    .checksum();

    println!("{}", packet);

    let packet_from = ipv4::Datagram::from(Vec::from(&packet).as_slice());

    println!("From: \n{}", packet_from);
}
