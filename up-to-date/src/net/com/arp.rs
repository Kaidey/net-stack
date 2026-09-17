use crate::net::com::{
    address::{self, HardwareAddress, ProtocolAddress},
    utils,
};
use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operation(u16);

impl Operation {
    pub const REQUEST: Self = Self(0x01);
    pub const REPLY: Self = Self(0x02);

    pub fn bits(self) -> u16 {
        self.0
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Operation::REQUEST => write!(f, "Request"),
            Operation::REPLY => write!(f, "Reply"),
            _ => write!(f, "Unknown Operation"),
        }
    }
}

pub struct Datagram {
    src_hardware_addr: address::HardwareAddress,
    dest_hardware_addr: address::HardwareAddress,
    src_proto_addr: address::ProtocolAddress,
    dest_proto_addr: address::ProtocolAddress,
    pub op: Operation,
    // TODO: Leave padding to Ethernet Frame
}

impl Datagram {
    pub fn new(
        src_hardware_addr: address::HardwareAddress,
        dest_hardware_addr: address::HardwareAddress,
        src_proto_addr: address::ProtocolAddress,
        dest_proto_addr: address::ProtocolAddress,
        operation: Operation,
    ) -> Self {
        let datagram = Self {
            src_hardware_addr: src_hardware_addr,
            dest_hardware_addr: dest_hardware_addr,
            src_proto_addr: src_proto_addr,
            dest_proto_addr: dest_proto_addr,
            op: operation,
        };

        datagram
    }
}

impl From<Datagram> for Vec<u8> {
    fn from(datagram: Datagram) -> Self {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&datagram.src_hardware_addr.codepoint().to_be_bytes());
        bytes.extend_from_slice(&datagram.src_proto_addr.codepoint().to_be_bytes());
        bytes.push(datagram.src_hardware_addr.length());
        bytes.push(datagram.src_proto_addr.length());
        bytes.extend_from_slice(&datagram.op.bits().to_be_bytes());
        bytes.extend_from_slice(&datagram.src_hardware_addr.addr());
        bytes.extend_from_slice(&datagram.src_proto_addr.addr());
        bytes.extend_from_slice(&datagram.dest_hardware_addr.addr());
        bytes.extend_from_slice(&datagram.dest_proto_addr.addr());

        bytes
    }
}

impl From<&[u8]> for Datagram {
    fn from(buffer: &[u8]) -> Self {
        let hardware_addr_type = u16::from_be_bytes([buffer[0], buffer[1]]);
        let proto_addr_type = u16::from_be_bytes([buffer[2], buffer[3]]);
        let hardware_addr_len = buffer[4] as usize;
        let proto_addr_len = buffer[5] as usize;

        let src_hardware_addr_start = 8;
        let src_proto_addr_start = src_hardware_addr_start + hardware_addr_len;
        let dest_hardware_addr_start = src_proto_addr_start + proto_addr_len;
        let dest_proto_addr_start = dest_hardware_addr_start + hardware_addr_len;

        Self {
            src_hardware_addr: HardwareAddress::from_wire(
                hardware_addr_type,
                &buffer[src_hardware_addr_start..src_proto_addr_start],
            )
            .expect("Idk"),
            dest_hardware_addr: HardwareAddress::from_wire(
                hardware_addr_type,
                &buffer[src_proto_addr_start..dest_hardware_addr_start],
            )
            .expect("Idk"),
            src_proto_addr: ProtocolAddress::from_wire(
                proto_addr_type,
                &buffer[dest_hardware_addr_start..dest_proto_addr_start],
            )
            .expect("Idk"),
            dest_proto_addr: ProtocolAddress::from_wire(
                proto_addr_type,
                &buffer[dest_proto_addr_start..proto_addr_len],
            )
            .expect("Idk"),
            op: Operation(u16::from_be_bytes([buffer[6], buffer[7]])),
        }
    }
}
impl fmt::Display for Datagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\nHardware Address Type: {}",
            self.src_hardware_addr
        )?;
        write!(
            f,
            "\nProtocol Address Type: {}",
            self.src_proto_addr
        )?;
        write!(f, "\nHardware Address Length: {:X}", self.src_hardware_addr.length())?;
        write!(f, "\nProtocol Address Length: {:X}", self.src_proto_addr.length())?;

        write!(f, "\nOperation: {}", self.op)?;

        write!(
            f,
            "Source Hardware Address: {}",
            self.src_hardware_addr.addr_as_string()
        )?;
        write!(
            f,
            "Source Protocol Address: {}",
            self.src_proto_addr.addr_as_string()
        )?;
        write!(
            f,
            "Destination Hardware Address: {}",
            self.dest_hardware_addr.addr_as_string()
        )?;
        write!(
            f,
            "Destination Protocol Address: {}",
            self.dest_proto_addr.addr_as_string()
        )?;

        Result::Ok(())
    }
}
