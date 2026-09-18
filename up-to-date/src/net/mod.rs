mod com;
mod socket;

// use crate::net::com::{address, arp, ethernet, ipv4, run_arp, tcp};
use crate::net::com::{
    address::{self, MacAddress},
    arp, ethernet, ipv4, run_arp, tcp,
};

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

        let dest_ip = com::address::IPv4Address::try_from("192.168.68.1")
            .map_err(|_| TcpError::InvalidAddress)?;
        // let dest_port_digits: Vec<u32> = slices[1]
        //     .chars()
        //     .map(|c| c.to_digit(radix))
        //     .collect::<Option<Vec<u32>>>()
        //     .ok_or(TcpError::InvalidPort)?;

        let src_ip = com::address::IPv4Address::try_from("192.168.68.101")
            .map_err(|_| TcpError::InvalidAddress)?;
        // let src_port_digits: Vec<u32> = slices[1]
        //     .chars()
        //     .map(|c| c.to_digit(radix))
        //     .collect::<Option<Vec<u32>>>()
        //     .ok_or(TcpError::InvalidPort)?;

        let src_mac =
            MacAddress::try_from("94-BB-43-4E-CE-BC").map_err(|_| TcpError::InvalidAddress)?;

        let sock_fd = socket::new_socket(Some(DEFAULT_NET_ITF));

        let target_mac = run_arp(sock_fd, src_mac, src_ip, dest_ip).unwrap();
        println!("Target MAC: {:02X?}", target_mac);
        //     // TODO: Init TCP Handshake

        Err(TcpError::InvalidAddress)
    }
}

pub fn test_parsing(dest_addr: &str) {
    let slices = dest_addr.split(":").collect::<Vec<&str>>();

    if slices.len() != 2 || slices[1].is_empty() {
        panic!("OH NO");
    }

    // Radix is the same as the base of the number system we want to use (base 10 here)
    let radix: u32 = 10;

    let dest_ip = com::address::IPv4Address::try_from(slices[0])
        .map_err(|_| TcpError::InvalidAddress)
        .expect("OH NO");

    let src_ip = com::address::IPv4Address::try_from(slices[0])
        .map_err(|_| TcpError::InvalidAddress)
        .expect("OH NO");

    let tcp_segment = tcp::Segment::new(
        src_ip,
        0x80,
        dest_ip,
        0x80,
        tcp::Flags::SYN,
        vec![1 as u8, 2 as u8, 3 as u8],
    );

    let ip_datagram = ipv4::Datagram::<tcp::Segment>::new(src_ip, dest_ip, tcp_segment)
        .or_else(|_| Err(TcpError::InvalidAddress))
        .expect("OH NO");

    let dest_mac = MacAddress::try_from("12-12-12-12-12-12").unwrap();
    let src_mac = MacAddress::try_from("21-21-21-21-21-21").unwrap();
    let eth_frame = ethernet::EthernetFrame::<ipv4::Datagram<tcp::Segment>>::new(
        dest_mac,
        src_mac,
        ip_datagram,
    );

    let frame_as_bytes: Vec<u8> = Vec::try_from(&eth_frame)
        .or_else(|_| Err(TcpError::InvalidPort))
        .expect("OH NO");

    println!("Frame:\n {}", eth_frame);

    let new_frame = ethernet::EthernetFrame::<ipv4::Datagram<tcp::Segment>>::try_from(
        frame_as_bytes.as_slice(),
    )
    .or_else(|_| Err(TcpError::InvalidAddress))
    .expect("OH NO");

    println!("\n\nFrame From Bytes:\n {}", new_frame);

    // Ok(Self {
    //     sock_fd: sock_fd,
    //     dest_ip: dest_ip,
    //     dest_port: dest_port.to_owned(),
    // })
}

//
// PARSING FRAMES FROM WIRE; IP EXAMPLE
// 0x0800 => {
//                 // Ethernet frame has 14 bytes of header. Next proto field is byte 10 (9 index) of an IPv4
//                 // header
//                 let next_proto_cp = buffer[14 + 9];
//                 let ipv4_payload = match next_proto_cp {
//                     tcp::Segment::CODEPOINT => {
//                         let frame = EthernetFrame::<ipv4::Datagram<tcp::Segment>>::try_from(
//                             buffer.as_slice(),
//                         )
//                         .ok()?;
//                         IPv4Payload::Tcp(frame.payload)
//                     }
//                     _ => {
//                         let frame =
//                             EthernetFrame::<ipv4::Datagram<ipv4::UnknownPayload>>::try_from(
//                                 buffer.as_slice(),
//                             )
//                             .ok()?;
//                         IPv4Payload::Unknown(frame.payload)
//                     }
//                 };
//                 EtherPayload::IPv4(ipv4_payload);
//             }
