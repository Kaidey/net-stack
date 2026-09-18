pub mod com;
pub mod socket;

// use crate::net::com::{address, arp, ethernet, ipv4, run_arp, tcp};
use crate::net::com::{
    address::{IPv4Address, MacAddress},
    ethernet, ipv4, run_arp, tcp,
};
use crate::os;

const DEFAULT_NET_ITF: &str = "eth1";

// TODO: Impl TcpListener

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
    GetSourceIp,
    GetSourceMac,
}

impl TcpConnection {
    pub fn new(dest_addr: &str) -> Result<Self, TcpError> {
        let src_ip_res: Option<[u8; 4]> =
            os::get_itf_ipv4_address(DEFAULT_NET_ITF).map_err(|_| TcpError::GetSourceIp)?;
        let src_ip = match src_ip_res {
            Some(ip) => IPv4Address::try_from(ip.as_slice()).or_else(|_| Err(TcpError::GetSourceIp))?,
            None => return Err(TcpError::GetSourceIp),
        };

        let src_mac_res: Option<String> =
            os::get_itf_mac_address(DEFAULT_NET_ITF).map_err(|_| TcpError::GetSourceMac)?;
        let src_mac = match src_mac_res {
            Some(mac) => {
                MacAddress::try_from(mac.as_str()).or_else(|_| Err(TcpError::GetSourceMac))?
            }
            None => return Err(TcpError::GetSourceMac),
        };

        let slices = dest_addr.split(":").collect::<Vec<&str>>();

        if slices.len() != 2 || slices[1].is_empty() {
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

        // let src_port_digits: Vec<u32> = slices[1]
        //     .chars()
        //     .map(|c| c.to_digit(radix))
        //     .collect::<Option<Vec<u32>>>()
        //     .ok_or(TcpError::InvalidPort)?;

        let sock_fd = socket::new_socket(Some(DEFAULT_NET_ITF));

        let dest_mac = run_arp(sock_fd, src_mac, src_ip, dest_ip).unwrap();
        //     // TODO: Init TCP Handshake

        Err(TcpError::InvalidAddress)
    }
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
