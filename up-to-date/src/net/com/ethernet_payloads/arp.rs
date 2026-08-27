use crate::net::com::{
    AddressFamily,
    ethernet_payloads::{self, utils},
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
    hardware_addr_family: AddressFamily,
    proto_addr_family: AddressFamily,
    pub op: Operation,
    pub src_hardware_addr: [u8; 6],
    pub src_proto_addr: [u8; 4],
    pub dest_hardware_addr: [u8; 6],
    pub dest_proto_addr: [u8; 4],
    // TODO: Leave padding to Ethernet Frame
}

impl Datagram {
    pub fn new(
        hardware_addr_family: AddressFamily,
        proto_addr_family: AddressFamily,
        operation: Operation,
        src_hardware_addr: [u8; 6],
        src_proto_addr: [u8; 4],
        dest_proto_addr: [u8; 4],
    ) -> Self {
        let datagram = Self {
            hardware_addr_family: hardware_addr_family,
            proto_addr_family: proto_addr_family,
            op: operation,
            src_hardware_addr: src_hardware_addr,
            src_proto_addr: src_proto_addr,
            dest_hardware_addr: [0, 0, 0, 0, 0, 0],
            dest_proto_addr: dest_proto_addr,
        };

        datagram
    }
}

impl From<Datagram> for Vec<u8> {
    fn from(datagram: Datagram) -> Self {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&datagram.hardware_addr_family.family_codepoint.to_be_bytes());
        bytes.extend_from_slice(&datagram.proto_addr_family.family_codepoint.to_be_bytes());
        bytes.push(datagram.hardware_addr_family.len);
        bytes.push(datagram.proto_addr_family.len);
        bytes.extend_from_slice(&datagram.op.bits().to_be_bytes());
        bytes.extend_from_slice(&datagram.src_hardware_addr);
        bytes.extend_from_slice(&datagram.src_proto_addr);
        bytes.extend_from_slice(&datagram.dest_hardware_addr);
        bytes.extend_from_slice(&datagram.dest_proto_addr);

        bytes
    }
}

impl From<Vec<u8>> for Datagram {
    fn from(buffer: Vec<u8>) -> Self {
        let mut datagram = Self {
            // Combines the first 2 u8 of buffer into a u16 by casting the first u8 to u16 and then
            // shifting it 8 bits left. Finally, performs an OR with the second u8
            hardware_addr_family: AddressFamily::from_family_codepoint(u16::from_be_bytes([
                buffer[0], buffer[1],
            ]))
            .unwrap(),
            proto_addr_family: AddressFamily::from_family_codepoint(u16::from_be_bytes([
                buffer[2], buffer[3],
            ]))
            .unwrap(),
            op: Operation(u16::from_be_bytes([buffer[6], buffer[7]])),
            src_hardware_addr: [0, 0, 0, 0, 0, 0],
            src_proto_addr: [0, 0, 0, 0],
            dest_hardware_addr: [0, 0, 0, 0, 0, 0],
            dest_proto_addr: [0, 0, 0, 0],
        };

        datagram.src_hardware_addr.copy_from_slice(&buffer[8..14]);
        datagram.src_proto_addr.copy_from_slice(&buffer[14..18]);
        datagram.dest_hardware_addr.copy_from_slice(&buffer[18..24]);
        datagram.dest_proto_addr.copy_from_slice(&buffer[24..28]);

        datagram
    }
}
impl fmt::Display for Datagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "\nHardware Address Type: {}",
            AddressFamily::name(&self.hardware_addr_family)
        );
        write!(f,
            "\nProtocol Address Type: {}",
            AddressFamily::name(&self.proto_addr_family)
        );
        write!(f,
            "\nHardware Address Length: {:X}",
            self.hardware_addr_family.len
        );
        write!(f,
            "\nProtocol Address Length: {:X}",
            self.proto_addr_family.len
        );

        write!(f,"\nOperation: {}", self.op);

        write!(f,
            "Source Hardware Address: {}",
            self.hardware_addr_family
                .addr_to_string(self.src_hardware_addr.to_vec())
        );
        write!(f,
            "Source Protocol Address: {}",
            self.proto_addr_family
                .addr_to_string(self.src_proto_addr.to_vec())
        );
        write!(f,
            "Destination Hardware Address: {}",
            self.hardware_addr_family
                .addr_to_string(self.dest_hardware_addr.to_vec())
        );
        write!(f,
            "Destination Protocol Address: {}",
            self.proto_addr_family
                .addr_to_string(self.dest_proto_addr.to_vec())
        );

        Result::Ok(())
    }
}
