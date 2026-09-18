use std::fmt;

use libc::{c_void, recv, send};

use crate::net::com::{
    address::{IPv4Address, MacAddress},
    arp::{Datagram, Operation},
    ethernet::EthernetFrame,
};

pub mod address;
pub mod arp;
pub mod ethernet;
pub mod ipv4;
pub mod tcp;
pub mod utils;

pub trait PduPayload {
    type Payload: fmt::Display;
    type ErrorSpace;
    type CodepointType;

    fn serialize_payload(payload: &Self::Payload) -> Result<Vec<u8>, Self::ErrorSpace>;
    fn deserialize_payload(
        codepoint: Self::CodepointType,
        payload: &[u8],
    ) -> Result<Self::Payload, Self::ErrorSpace>;
    fn codepoint(payload: &Self::Payload) -> Self::CodepointType;
    fn name() -> String;
}

pub fn run_arp(
    socket_fd: i32,
    src_mac: MacAddress,
    src_ip: IPv4Address,
    dest_ip: IPv4Address,
) -> Option<[u8; 6]> {
    // TODO: Error handling
    let dest_mac = MacAddress::try_from("00-00-00-00-00-00").expect("Wrong Broadcast MAC");

    let arp_datagram = Datagram::new(
        address::HardwareAddress::MAC(src_mac.clone()),
        address::HardwareAddress::MAC(dest_mac.clone()),
        address::ProtocolAddress::IPv4(src_ip),
        address::ProtocolAddress::IPv4(dest_ip),
        Operation::REQUEST,
    );

    let outbound_frame = EthernetFrame::<arp::Datagram>::new(dest_mac, src_mac, arp_datagram);

    let frame_as_bytes = Vec::try_from(&outbound_frame).expect("Wrong");

    let bytes_sent = unsafe {
        send(
            socket_fd,
            frame_as_bytes.as_ptr() as *const _,
            frame_as_bytes.len(),
            0,
        )
    };

    if bytes_sent < 0 {
        println!(
            "Failed to send ARP request: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut buffer = [0u8; 65536];

    // Handle reply not being received
    // threads?
    // Retries with limit wait time?
    loop {
        let frame_size = unsafe {
            recv(
                socket_fd,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                0,
            )
        };

        if frame_size < 0 {
            panic!("Error receiving frame: {}", std::io::Error::last_os_error());
        }

        let eth_type = u16::from_be_bytes([buffer[12], buffer[13]]);

        match eth_type {
            // TODO: Review, maybe swap to Enum
            0x0806 => {
                let inbound_frame =
                    EthernetFrame::<arp::Datagram>::try_from(buffer.as_slice()).ok()?;

                if inbound_frame.payload.src_proto_addr == outbound_frame.payload.dest_proto_addr
                    && inbound_frame.payload.op == Operation::REPLY
                {
                    println!("Buffer: {:02X?}", buffer);
                    let mut target_mac = [0; 6];
                    target_mac
                        .copy_from_slice(inbound_frame.payload.src_hardware_addr.addr_bytes());
                    return Some(target_mac);
                }
            }
            _ => {}
        };
    }
}
