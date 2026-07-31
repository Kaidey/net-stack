use core::fmt;
use std::{array, fmt::UpperHex, io::Error, str::FromStr, string::FromUtf8Error};
use libc::{c_void, recv, send};

pub mod ethernet_payloads;
use ethernet_payloads::{arp, ipv4, ipv6};

use crate::net::com::ethernet_payloads::arp::ArpPacket;

pub struct EthernetFrame {
    dest_mac_address: [u8; 6],
    src_mac_address: [u8; 6],
    // Type or length of the payload
    type_or_length: u16,
    data: Vec<u8>,
}

impl EthernetFrame {
    pub fn new(
        dest_mac_address: [u8; 6],
        src_mac_address: [u8; 6],
        type_or_length: u16,
        data: Vec<u8>,
    ) -> Self {
        Self {
            dest_mac_address: dest_mac_address,
            src_mac_address: src_mac_address,
            type_or_length: type_or_length,
            data: data,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.dest_mac_address);
        bytes.extend_from_slice(&self.src_mac_address);
        bytes.extend_from_slice(&self.type_or_length.to_be_bytes());
        bytes.extend_from_slice(&self.data);

        bytes
    }
}

impl From<Vec<u8>> for EthernetFrame {
    fn from(buffer: Vec<u8>) -> Self {
        let mut eth_frame = Self {
            dest_mac_address: [0, 0, 0, 0, 0, 0],
            src_mac_address: [0, 0, 0, 0, 0, 0],
            // Adds (binary OR) bytes 12 and 13 from the buffer (2 bytes for frame
            // type/length) in order to convert the separate bytes into a u16
            // Example with frame type = ARP:
            //      [08,06] -> 0806(u16)
            type_or_length: ((buffer[12] as u16) << 8) | buffer[13] as u16,
            data: buffer[14..].to_vec(),
        };

        eth_frame.dest_mac_address.copy_from_slice(&buffer[0..6]);
        eth_frame.src_mac_address.copy_from_slice(&buffer[6..12]);

        eth_frame
    }
}

impl fmt::Display for EthernetFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut serialized_data: Option<PacketType> = None;

        for frame_type in FrameType::variations_as_vec().iter() {
            if frame_type.hex_value() == self.type_or_length {
                serialized_data = FrameType::serialize_payload(frame_type, self.data.clone()) //frame_type.serialize_payload(self.data.clone());
            }
        }

        println!(
            "\nDestination MAC: {}",
            AddressFamily::to_string(&AddressFamily::MAC, self.dest_mac_address.to_vec())
        );
        println!(
            "Source MAC: {}",
            AddressFamily::to_string(&AddressFamily::MAC, self.src_mac_address.to_vec())
        );
        println!(
            "Frame Type/Length: {:04X?} ({})",
            self.type_or_length,
            FrameType::name_from_u16(self.type_or_length)
        );

        match serialized_data {
            Some(PacketType::Arp(arp)) => println!("{}", arp),
            Some(PacketType::IPv4(ipv4)) => println!("{}", ipv4),
            Some(PacketType::IPv6(ipv6)) => println!("{}", ipv6),
            None => println!("Unknown payload type"),
        }

        fmt::Result::Ok(())
    }
}
pub enum PacketType {
    Arp(arp::ArpPacket),
    IPv4(ipv4::IPv4Packet),
    IPv6(ipv6::IPv6Packet),
}
#[repr(u16)]
#[derive(PartialEq, Eq, Copy)]
pub enum FrameType {
    Arp = 0x0806,
    IPv4 = 0x0800,
    IPv6 = 0x86DD,
}

impl FrameType {
    pub fn name_from_u16(value: u16) -> &'static str {
        match value {
            0x0806 => "ARP",
            0x0800 => "IPv4",
            0x86DD => "IPv6",
            _ => "Unknown",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            FrameType::Arp => "ARP",
            FrameType::IPv4 => "IPv4",
            FrameType::IPv6 => "IPv6",
        }
    }

    pub fn hex_value(self) -> u16 {
        self as u16
    }
    pub fn variations_as_vec() -> Vec<FrameType> {
        vec![FrameType::Arp, FrameType::IPv4, FrameType::IPv6]
    }

    pub fn serialize_payload(&self, bytes: Vec<u8>) -> Option<PacketType> {
        match self {
            FrameType::Arp => Some(PacketType::Arp(bytes.into())),
            // FrameType::IPv4 => Some(PacketType::IPv4(bytes.into())),
            // FrameType::IPv6 => Some(PacketType::IPv6(bytes.into())),
            _ => None,
        }
    }
}

impl Clone for FrameType {
    fn clone(&self) -> Self {
        self.to_owned()
    }
}

pub struct AddressFamily {
    pub family: u16,
    pub len: u8,
}

impl AddressFamily {
    pub const MAC: Self = Self { family: 1, len: 6 };
    pub const IPV4: Self = Self {
        family: 2048,
        len: 4,
    };
    pub fn name(&self) -> &'static str {
        match self.family {
            family if family == AddressFamily::MAC.family => "MAC",
            family if family == AddressFamily::IPV4.family => "IPv4",
            _ => "Unknown Address Family",
        }
    }
    fn to_string(&self, bytes: Vec<u8>) -> String {
        match self.family {
            family if family == AddressFamily::MAC.family => bytes
                .iter()
                .map(|byte| format!("{:02X?}", byte))
                .collect::<Vec<_>>()
                .join("-"),
            family if family == AddressFamily::IPV4.family => bytes
                .iter()
                .map(|byte| format!("{:#}", byte))
                .collect::<Vec<_>>()
                .join("."),
            _ => String::from("Unknown Address Family"),
        }
    }
    fn from_family(family: u16) -> Option<Self> {
        match family {
            family if family == AddressFamily::MAC.family => Some(AddressFamily::MAC),
            family if family == AddressFamily::IPV4.family => Some(AddressFamily::IPV4),
            _ => None,
        }
    }
}

pub fn run_arp(socket_fd: i32, src_mac: [u8; 6], src_ip: [u8; 4], dest_ip: [u8; 4]) -> Option<[u8; 6]> {
    let arp_packet = arp::ArpPacket::new_request(
        AddressFamily::MAC,
        AddressFamily::IPV4,
        src_mac,
        src_ip,
        [0, 0, 0, 0, 0, 0],
        dest_ip,
    );

    let eth_frame = EthernetFrame::new(
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        src_mac,
        FrameType::Arp.hex_value(),
        arp_packet.to_bytes(),
    );

    let frame_as_bytes: Vec<u8> = eth_frame.to_bytes();

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
    // Since new_socket() is a generic, we need to tell the compiler what type None should be
    // treated as. The function expects any type that implements Into<String>, so we tell the comp
    // to treat None as a String

    let mut buffer = [0u8; 65536];

    let mut dest_mac: Option<[u8; 6]> = None;

    // Make sure to only capture replies to my request (op = reply, dest_mac = input src_marc,
    // dest_ip = input src_ip, src_ip = input dest_ip
    //
    // Handle reply not being received
    // threads?
    // loop has to go
    // Retries with limit wait time?
    loop {
        let frame_size =
            unsafe { recv(socket_fd, buffer.as_mut_ptr() as *mut c_void, buffer.len(), 0) };

        if frame_size < 0 {
            panic!("Error receiving frame: {}", std::io::Error::last_os_error());
        }

        let frame: EthernetFrame = EthernetFrame::from(buffer.to_vec());
        let is_arp: ArpPacket = ArpPacket::from(frame.data);

        if is_arp.op == 0x0002 && is_arp.dest_hardware_addr == src_mac{
            dest_mac = Some(is_arp.src_hardware_addr);
            break;
        }
    }

    dest_mac
}
