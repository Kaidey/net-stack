use core::fmt;
use std::{array, fmt::UpperHex, io::Error, str::FromStr, string::FromUtf8Error};

pub struct EthernetFrame {
    dest_mac_address: [u8; 6],
    source_mac_address: [u8; 6],
    // Type or length of the payload
    type_or_length: u16,
    data: Vec<u8>,
}

impl EthernetFrame {
    pub fn new(
        dest_mac_address: [u8; 6],
        source_mac_address: [u8; 6],
        type_or_length: u16,
        data: Vec<u8>,
    ) -> Self {
        Self {
            dest_mac_address: dest_mac_address,
            source_mac_address: source_mac_address,
            type_or_length: type_or_length,
            data: data,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.dest_mac_address);
        bytes.extend_from_slice(&self.source_mac_address);
        bytes.extend_from_slice(&self.type_or_length.to_be_bytes());
        bytes.extend_from_slice(&self.data);

        bytes
    }
}

impl From<Vec<u8>> for EthernetFrame {
    fn from(buffer: Vec<u8>) -> Self {
        let mut eth_frame = EthernetFrame {
            dest_mac_address: [0, 0, 0, 0, 0, 0],
            source_mac_address: [0, 0, 0, 0, 0, 0],
            // Adds (binary OR) bytes 12 and 13 from the buffer (2 bytes for frame
            // type/length) in order to convert the separate bytes into a u16
            // Example with frame type = ARP:
            //      [08,06] -> 0806(u16)
            type_or_length: ((buffer[12] as u16) << 8) | buffer[13] as u16,
            data: buffer[14..].to_vec(),
        };

        eth_frame.dest_mac_address.copy_from_slice(&buffer[0..6]);
        eth_frame.source_mac_address.copy_from_slice(&buffer[6..12]);

        eth_frame
    }
}

impl fmt::Display for EthernetFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dest_mac_disp_string: String = String::new();
        let mut byte_counter: i32 = 0;
        for byte in self.dest_mac_address.iter() {
            fmt::write(&mut dest_mac_disp_string, format_args!("{:02X?}", byte));
            if byte_counter != (self.dest_mac_address.len() - 1) as i32 {
                fmt::write(&mut dest_mac_disp_string, format_args!("-"));
            }
            byte_counter += 1;
        }

        // write!(f, "\nDestination MAC: {dest_mac_disp_string}")

        let mut src_mac_disp_string: String = String::new();
        byte_counter = 0;
        for byte in self.source_mac_address.iter() {
            fmt::write(&mut src_mac_disp_string, format_args!("{:02X?}", byte));
            if byte_counter != (self.dest_mac_address.len() - 1) as i32 {
                fmt::write(&mut src_mac_disp_string, format_args!("-"));
            }
            byte_counter += 1;
        }

        let mut serialized_data: Option<PacketType> = None;

        for frame_type in FrameType::variations_as_vec().iter() {
            if frame_type.hex_value() == self.type_or_length {
                serialized_data = FrameType::serialize_payload(frame_type, self.data.clone())//frame_type.serialize_payload(self.data.clone());
            }
        }

        write!(
            f,
            "\nDestination MAC: {dest_mac_disp_string}\nSource MAC: {src_mac_disp_string}\nFrame Type/Length: {:04X?} ({}),\nPayload: {}",
            self.type_or_length,
            FrameType::name_from_u16(self.type_or_length),
            serialized_data.unwrap()
        )
    }
}
pub enum PacketType {
    Arp(ArpPacket),
    IPv4(IPv4Packet),
    IPv6(IPv6Packet)
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
            _ => None
        }
    }
}

impl Clone for FrameType {
    fn clone(&self) -> Self{
        self.to_owned()
    }
}

pub struct Address {
    addr_type: u16,
    addr_len: u8,
}

pub struct ArpAddressTypes;

impl ArpAddressTypes {
    pub const ETHERNET: Address = Address {
        addr_type: 0x0001,
        addr_len: 0x06,
    };
    pub const IPV4: Address = Address {
        addr_type: 0x0800,
        addr_len: 0x04,
    };
}
#[repr(u16)]
pub enum ArpOperations {
    Request = 0x0001,
    Reply = 0x0002,
}

impl ArpOperations {
    pub fn hex_value(self) -> u16 {
        self as u16
    }
}

pub struct ArpPacket {
    hardware_addr_type: u16,
    proto_addr_type: u16,
    hardware_addr_len: u8,
    proto_addr_len: u8,
    op: u16,
    src_hardware_addr: [u8; 6],
    src_proto_addr: [u8; 4],
    dest_hardware_addr: [u8; 6],
    dest_proto_addr: [u8; 4],
    padding: Vec<u8>,
}

impl ArpPacket {
    pub fn new_arp_request_packet(
        hardware_addr: Address,
        proto_addr: Address,
        src_hardware_addr: [u8; 6],
        src_proto_addr: [u8; 4],
        dest_hardware_addr: [u8; 6],
        dest_proto_addr: [u8; 4],
    ) -> Self {
        let mut packet = Self {
            hardware_addr_type: hardware_addr.addr_type,
            proto_addr_type: proto_addr.addr_type,
            hardware_addr_len: hardware_addr.addr_len,
            proto_addr_len: proto_addr.addr_len,
            op: ArpOperations::Request.hex_value(),
            src_hardware_addr: src_hardware_addr,
            src_proto_addr: src_proto_addr,
            dest_hardware_addr: dest_hardware_addr,
            dest_proto_addr: dest_proto_addr,
            padding: vec![],
        };

        packet.add_padding();
        packet
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.hardware_addr_type.to_be_bytes());
        bytes.extend_from_slice(&self.proto_addr_type.to_be_bytes());
        bytes.push(self.hardware_addr_len);
        bytes.push(self.proto_addr_len);
        bytes.extend_from_slice(&self.op.to_be_bytes());
        bytes.extend_from_slice(&self.src_hardware_addr);
        bytes.extend_from_slice(&self.src_proto_addr);
        bytes.extend_from_slice(&self.dest_hardware_addr);
        bytes.extend_from_slice(&self.dest_proto_addr);
        bytes.extend_from_slice(&self.padding);

        bytes
    }
    fn add_padding(&mut self) {
        let mut packet_as_bytes = self.to_bytes();
        // println!(
        //     "Padding Arp packet. Starting size: {}",
        //     packet_as_bytes.len()
        // );

        while packet_as_bytes.len() < 40 {
            self.padding.push(0);
            packet_as_bytes = self.to_bytes();
        }
    }
}
impl From<Vec<u8>> for ArpPacket {
    // TEMP
    fn from(buffer: Vec<u8>) -> Self {
        ArpPacket::new_arp_request_packet(
            ArpAddressTypes::ETHERNET,
            ArpAddressTypes::IPV4,
            [0x94, 0xbb, 0x43, 0x4e, 0xce, 0xbc],
            [192, 168, 68, 101],
            [0, 0, 0, 0, 0, 0],
            [192, 168, 68, 100],
        )
    }
}
impl fmt::Display for ArpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.to_bytes() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

pub struct IPv4Packet {}
pub struct IPv6Packet {}
