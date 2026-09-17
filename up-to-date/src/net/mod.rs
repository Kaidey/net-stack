mod com;
mod socket;

// use crate::net::com::{address, arp, ethernet, ipv4, run_arp, tcp};
use crate::net::com::{address, arp, ethernet, ipv4, tcp};

const DEFAULT_NET_ITF: &str = "eth1";

pub struct TcpConnection {
    sock_fd: i32,
    dest_ip: [u8; 4],
    dest_port: u16,
}

#[derive(Debug)]
pub enum TcpError {
    InvalidPort,
    InvalidAddress,
    MalformedAddressString,
}

impl TcpConnection {
    pub fn new(dest_addr: &str) -> Result<Self, TcpError> {
        let slices = dest_addr.split(":").collect::<Vec<&str>>();

        if slices.len() != 2 || slices[1].is_empty() {
            println!("Ha err");
            return Err(TcpError::MalformedAddressString);
        }

        // Radix is the same as the base of the number system we want to use (base 10 here)
        let radix: u32 = 10;

        let dest_ip = com::address::IPv4Address::try_from(slices[0]).map_err(|_| TcpError::InvalidAddress)?;
        let dest_port_digits: Vec<u32> = slices[1]
            .chars()
            .map(|c| c.to_digit(radix))
            .collect::<Option<Vec<u32>>>()
            .ok_or(TcpError::InvalidPort)?;

        println!("IP: {}", dest_ip);
        println!("Port: {:?}", dest_port_digits);

        return Err(TcpError::MalformedAddressString);

        //     let sock_fd = socket::new_socket(Some(DEFAULT_NET_ITF));
        //     // TODO: Init TCP Handshake
        //     let tcp_segment = tcp::Segment::new(
        //         src_ip,
        //         src_port,
        //         dest_ip,
        //         dest_port,
        //         tcp::Flags::SYN,
        //         payload,
        //     );
        //
        //     let ip_datagram =
        //         ipv4::Datagram::new(ipv4::Protocol::TCP, src_addr, dest_ip, tcp_segment.into());
        //
        //     // TODO: Run ARP
        //
        //     let eth_frame = ethernet::EthernetFrame::new(
        //         dest_mac,
        //         src_mac,
        //         ethernet::EtherType::IPv4,
        //         ip_datagram.into(),
        //     );
        //
        //     Ok(Self {
        //         sock_fd: sock_fd,
        //         dest_ip: dest_ip,
        //         dest_port: dest_port.to_owned(),
        //     })
    }
}

// pub fn test() {
//     // let sock_fd = socket::new_socket(Some("eth1"));
//
//     // let dest_mac: Option<[u8; 6]> = run_arp(
//     //     sock_fd,
//     //     [0x94, 0xBB, 0x43, 0x4E, 0xCE, 0xBC],
//     //     [192, 168, 68, 101],
//     //     [192, 168, 68, 100],
//     // );
//     //
//     // println!("Destination MAC: {:02X?}", dest_mac.unwrap());
//
//     let tcp: tcp::Segment = tcp::Segment::new(
//         &[192 as u8, 168 as u8, 68 as u8, 1 as u8],
//         1,
//         &[192 as u8, 172 as u8, 50 as u8, 1 as u8],
//         2,
//         tcp::Flags::SYN,
//         vec![1, 2],
//     )
//     .checksum(
//         &[192 as u8, 168 as u8, 68 as u8, 1 as u8],
//         &[192 as u8, 172 as u8, 50 as u8, 1 as u8],
//         ipv4::Protocol::TCP.bits(),
//     );
//
//     let packet: ipv4::Datagram = ipv4::Datagram::new(
//         ipv4::Protocol::TCP,
//         [192, 168, 68, 1],
//         [192, 172, 50, 1],
//         Vec::from(&tcp),
//     )
//     .unwrap()
//     .ttl(128)
//     .flags(ipv4::FragmentationFlags::MORE_FRAGMENTS)
//     .fragment_offset(0xB1)
//     .dscp(ipv4::Dscp::AF21)
//     .checksum();
//
//     println!("{}", packet);
//
//     let packet_from = ipv4::Datagram::from(Vec::from(&packet).as_slice());
//
//     println!("From: \n{}", packet_from);
// }
