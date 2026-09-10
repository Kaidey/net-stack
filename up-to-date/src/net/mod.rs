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

    // let tcp: tcp::Segment = tcp::Segment::new(1, 2, tcp::Flags::SYN, vec![1, 2]).checksum(
    //     &[192 as u8, 168 as u8, 68 as u8, 1 as u8],
    //     &[192 as u8, 172 as u8, 50 as u8, 1 as u8],
    //     ipv4::Protocol::TCP.bits(),
    // );
    //
    // let packet: ipv4::Datagram = ipv4::Datagram::new(
    //     ipv4::Protocol::TCP,
    //     [192, 168, 68, 1],
    //     [192, 172, 50, 1],
    //     Vec::from(&tcp),
    // )
    // .unwrap()
    // .ttl(128)
    // .flags(ipv4::FragmentationFlags::MORE_FRAGMENTS)
    // .fragment_offset(0xB1)
    // .dscp(ipv4::Dscp::AF21)
    // .checksum();
    //
    // println!("{}", packet);
    //
    // let packet_from = ipv4::Datagram::from(Vec::from(&packet).as_slice());
    //
    // println!("From: \n{}", packet_from);

    println!("###### SHA_256 Test Vectors ######");
    println!("");
    println!(
        "Input: <emtpy>\nHash: {}",
        crypto::sha_256::hash("".to_string().into_bytes().as_slice())
    );
    println!(
        "Input: abc\nHash: {}",
        crypto::sha_256::hash("abc".to_string().into_bytes().as_slice())
    );
    let hex_str = "de188941a3375d3a8a061e67576e926d";
    let bytes: Vec<u8> = (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
        .collect();
    println!(
        "Input: {}\nHash: {}",
        hex_str,
        crypto::sha_256::hash(&bytes)
    );

    let hex_str2 = "de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e";
    let bytes2: Vec<u8> = (0..hex_str2.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str2[i..i + 2], 16).unwrap())
        .collect();
    println!(
        "Input: {}\nHash: {}",
        hex_str2,
        crypto::sha_256::hash(&bytes2)
    );
    // let rand = "abc".to_string().into_bytes();
    // let mut bin = "".to_string();
    // for charr in rand {
    //     bin += &format!("{:b}", charr);
    // }
    // println!("'abc' in bin is {}", bin);
}
