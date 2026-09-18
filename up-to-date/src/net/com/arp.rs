use crate::net::com::{
    PduPayload,
    address::{self, HardwareAddress, ProtocolAddress},
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub src_hardware_addr: address::HardwareAddress,
    pub dest_hardware_addr: address::HardwareAddress,
    pub src_proto_addr: address::ProtocolAddress,
    pub dest_proto_addr: address::ProtocolAddress,
    pub op: Operation,
    // TODO: Leave padding to Ethernet Frame
}

impl Datagram {
    pub const CODEPOINT: u16 = 0x0806;
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

// TODO: Error handling
pub enum ArpError {
    InvalidDatagram,
    ProtocolMismatch,
}

impl PduPayload for Datagram {
    type Payload = Datagram;
    type ErrorSpace = ArpError;
    type CodepointType = u16;

    fn serialize_payload(payload: &Self::Payload) -> Result<Vec<u8>, Self::ErrorSpace> {
        let vec = Vec::try_from(payload).or_else(|_| Err(ArpError::InvalidDatagram))?;
        Ok(vec)
    }

    fn deserialize_payload(
        cp: Self::CodepointType,
        payload: &[u8],
    ) -> Result<Self::Payload, Self::ErrorSpace> {
        if cp != Self::CODEPOINT {
            return Err(ArpError::ProtocolMismatch);
        }
        let seg = Datagram::try_from(payload).or_else(|_| Err(ArpError::InvalidDatagram))?;
        Ok(seg)
    }
    fn codepoint(_payload: &Self::Payload) -> Self::CodepointType {
        Self::CODEPOINT
    }
    fn name() -> String {
        String::from("ARP")
    }
}

impl TryFrom<&Datagram> for Vec<u8> {
    type Error = ArpError;

    fn try_from(datagram: &Datagram) -> Result<Self, Self::Error> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&datagram.src_hardware_addr.codepoint().to_be_bytes());
        bytes.extend_from_slice(&datagram.src_proto_addr.codepoint().to_be_bytes());
        bytes.push(datagram.src_hardware_addr.length());
        bytes.push(datagram.src_proto_addr.length());
        bytes.extend_from_slice(&datagram.op.bits().to_be_bytes());
        bytes.extend_from_slice(&datagram.src_hardware_addr.addr_bytes());
        bytes.extend_from_slice(&datagram.src_proto_addr.addr_bytes());
        bytes.extend_from_slice(&datagram.dest_hardware_addr.addr_bytes());
        bytes.extend_from_slice(&datagram.dest_proto_addr.addr_bytes());

        Ok(bytes)
    }
}

impl TryFrom<&[u8]> for Datagram {
    type Error = ArpError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let hardware_addr_type = u16::from_be_bytes([buffer[0], buffer[1]]);
        let proto_addr_type = u16::from_be_bytes([buffer[2], buffer[3]]);
        let hardware_addr_len = buffer[4] as usize;
        let proto_addr_len = buffer[5] as usize;

        let src_hardware_addr_start = 8;
        let src_proto_addr_start = src_hardware_addr_start + hardware_addr_len;
        let dest_hardware_addr_start = src_proto_addr_start + proto_addr_len;
        let dest_proto_addr_start = dest_hardware_addr_start + hardware_addr_len;
        let dest_proto_addr_end = dest_proto_addr_start + proto_addr_len;

        Ok(Self {
            src_hardware_addr: HardwareAddress::from_wire(
                hardware_addr_type,
                &buffer[src_hardware_addr_start..src_proto_addr_start],
            )
            .expect("src mac failed"),
            src_proto_addr: ProtocolAddress::from_wire(
                proto_addr_type,
                &buffer[src_proto_addr_start..dest_hardware_addr_start],
            )
            .expect("Idk"),
            dest_hardware_addr: HardwareAddress::from_wire(
                hardware_addr_type,
                &buffer[dest_hardware_addr_start..dest_proto_addr_start],
            )
            .expect("dest mac failed"),
            dest_proto_addr: ProtocolAddress::from_wire(
                proto_addr_type,
                &buffer[dest_proto_addr_start..dest_proto_addr_end],
            )
            .expect("Idk"),
            op: Operation(u16::from_be_bytes([buffer[6], buffer[7]])),
        })
    }
}
impl fmt::Display for Datagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\nHardware Address Type: {}", self.src_hardware_addr)?;
        write!(f, "\nProtocol Address Type: {}", self.src_proto_addr)?;
        write!(
            f,
            "\nHardware Address Length: {:X}",
            self.src_hardware_addr.length()
        )?;
        write!(
            f,
            "\nProtocol Address Length: {:X}",
            self.src_proto_addr.length()
        )?;

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
