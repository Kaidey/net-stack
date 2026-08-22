mod com;
mod socket;

use std::str::FromStr;

use com::ethernet_payloads::{arp, ipv4};
use com::{AddressFamily, EthernetFrame};
use libc::{c_void, recv, send};

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
   ipv4::IPv4Packet::new(ipv4::Protocol::ICMP, [192,168,68,1], [192,172,50,1],vec![1,2]).ttl(64).tos(ipv4::phb::EXPEDITED_FORWARDING); 
}
