use std::fmt::{self, Display};

use libc::{c_void, recv, send};

pub mod address;
pub mod arp;
pub mod ethernet;
pub mod ipv4;
pub mod tcp;
pub mod utils;

pub trait PduPayload {
    type Payload: Display;
    type ErrorSpace;
    type CodepointType;

    const CODEPOINT: Self::CodepointType;

    fn serialize_payload(payload: &Self::Payload) -> Result<Vec<u8>, Self::ErrorSpace>;
    fn deserialize_payload(payload: &[u8]) -> Result<Self::Payload, Self::ErrorSpace>;
}

// pub fn run_arp(
//     socket_fd: i32,
//     src_mac: [u8; 6],
//     src_ip: [u8; 4],
//     dest_ip: [u8; 4],
// ) -> Option<[u8; 6]> {
//     let x = arp::Datagram::new::<IPv4Address>();
//     let arp_packet = arp::Datagram::new(
//         AddressFamily::MAC,
//         AddressFamily::IPV4,
//         arp::Operation::REQUEST,
//         src_mac,
//         src_ip,
//         dest_ip,
//     );
//
//     let eth_frame = EthernetFrame::new(
//         [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
//         src_mac,
//         FrameType::Arp.hex_value(),
//         arp_packet.into(),
//     );
//
//     let frame_as_bytes: Vec<u8> = eth_frame.to_bytes();
//
//     let bytes_sent = unsafe {
//         send(
//             socket_fd,
//             frame_as_bytes.as_ptr() as *const _,
//             frame_as_bytes.len(),
//             0,
//         )
//     };
//
//     if bytes_sent < 0 {
//         println!(
//             "Failed to send ARP request: {}",
//             std::io::Error::last_os_error()
//         );
//     }
//     // Since new_socket() is a generic, we need to tell the compiler what type None should be
//     // treated as. The function expects any type that implements Into<String>, so we tell the comp
//     // to treat None as a String
//
//     let mut buffer = [0u8; 65536];
//
//     let mut dest_mac: Option<[u8; 6]> = None;
//
//     // Make sure to only capture replies to my request (op = reply, dest_mac = input src_marc,
//     // dest_ip = input src_ip, src_ip = input dest_ip
//     //
//     // Handle reply not being received
//     // threads?
//     // loop has to go
//     // Retries with limit wait time?
//     loop {
//         let frame_size = unsafe {
//             recv(
//                 socket_fd,
//                 buffer.as_mut_ptr() as *mut c_void,
//                 buffer.len(),
//                 0,
//             )
//         };
//
//         if frame_size < 0 {
//             panic!("Error receiving frame: {}", std::io::Error::last_os_error());
//         }
//
//         let frame: EthernetFrame = EthernetFrame::from(buffer.to_vec());
//         let is_arp: Datagram = Datagram::from(frame.payload);
//
//         if is_arp.op == arp::Operation::REPLY && is_arp.dest_hardware_addr == src_mac {
//             dest_mac = Some(is_arp.src_hardware_addr);
//             break;
//         }
//     }
//
//     dest_mac
// }
