use crate::net::com::{
    AddressFamily,
    ethernet_payloads::{self, utils},
};
use core::fmt;

pub struct Datagram {
    hardware_addr_family: AddressFamily,
    proto_addr_family: AddressFamily,
    pub op: u16,
    pub src_hardware_addr: [u8; 6],
    pub src_proto_addr: [u8; 4],
    pub dest_hardware_addr: [u8; 6],
    pub dest_proto_addr: [u8; 4],
    padding: Vec<u8>,
}

impl Datagram {
    pub fn new_request(
        hardware_addr_family: AddressFamily,
        proto_addr_family: AddressFamily,
        src_hardware_addr: [u8; 6],
        src_proto_addr: [u8; 4],
        dest_hardware_addr: [u8; 6],
        dest_proto_addr: [u8; 4],
    ) -> Self {
        let mut datagram = Self {
            hardware_addr_family: hardware_addr_family,
            proto_addr_family: proto_addr_family,
            op: 0x0001,
            src_hardware_addr: src_hardware_addr,
            src_proto_addr: src_proto_addr,
            dest_hardware_addr: dest_hardware_addr,
            dest_proto_addr: dest_proto_addr,
            padding: vec![],
        };

        utils::fixed_size_header_padding(datagram.to_bytes().len(), 40, &mut datagram.padding);
        datagram
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.hardware_addr_family.family_codepoint.to_be_bytes());
        bytes.extend_from_slice(&self.proto_addr_family.family_codepoint.to_be_bytes());
        bytes.push(self.hardware_addr_family.len);
        bytes.push(self.proto_addr_family.len);
        bytes.extend_from_slice(&self.op.to_be_bytes());
        bytes.extend_from_slice(&self.src_hardware_addr);
        bytes.extend_from_slice(&self.src_proto_addr);
        bytes.extend_from_slice(&self.dest_hardware_addr);
        bytes.extend_from_slice(&self.dest_proto_addr);
        bytes.extend_from_slice(&self.padding);

        bytes
    }
}
impl From<Vec<u8>> for Datagram {
    fn from(buffer: Vec<u8>) -> Self {
        let mut datagram = Self {
            // Combines the first 2 u8 of buffer into a u16 by casting the first u8 to u16 and then
            // shifting it 8 bits left. Finally, performs an OR with the second u8
            hardware_addr_family: AddressFamily::from_family_codepoint(
                ((buffer[0] as u16) << 8) | buffer[1] as u16,
            )
            .unwrap(),
            proto_addr_family: AddressFamily::from_family_codepoint(
                ((buffer[2] as u16) << 8) | buffer[3] as u16,
            )
            .unwrap(),
            op: (buffer[6] as u16) << 8 | buffer[7] as u16,
            src_hardware_addr: [0, 0, 0, 0, 0, 0],
            src_proto_addr: [0, 0, 0, 0],
            dest_hardware_addr: [0, 0, 0, 0, 0, 0],
            dest_proto_addr: [0, 0, 0, 0],
            padding: buffer[28..].to_vec(),
        };

        datagram.src_hardware_addr.copy_from_slice(&buffer[8..14]);
        datagram.src_proto_addr.copy_from_slice(&buffer[14..18]);
        datagram.dest_hardware_addr.copy_from_slice(&buffer[18..24]);
        datagram.dest_proto_addr.copy_from_slice(&buffer[24..28]);

        datagram
    }
}
impl fmt::Display for Datagram {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        println!(
            "Hardware Address Type: {:04?} ({})",
            self.hardware_addr_family.family_codepoint,
            AddressFamily::name(&self.hardware_addr_family)
        );
        println!(
            "Protocol Address Type: {:04X?} ({})",
            self.proto_addr_family.family_codepoint,
            AddressFamily::name(&self.proto_addr_family)
        );
        println!(
            "Hardware Address Length: {:02X?}",
            self.hardware_addr_family.len
        );
        println!(
            "Protocol Address Length: {:02X?}",
            self.proto_addr_family.len
        );

        match self.op {
            0x0001 => println!("Operation: {:04?} ({})", self.op, "Request"),
            0x0002 => println!("Operation: {:04?} ({})", self.op, "Reply"),
            _ => println!("Unknown Operation"),
        }

        println!(
            "Source Hardware Address: {}",
            self.hardware_addr_family
                .addr_to_string(self.src_hardware_addr.to_vec())
        );
        println!(
            "Source Protocol Address: {}",
            self.proto_addr_family
                .addr_to_string(self.src_proto_addr.to_vec())
        );
        println!(
            "Destination Hardware Address: {}",
            self.hardware_addr_family
                .addr_to_string(self.dest_hardware_addr.to_vec())
        );
        println!(
            "Destination Protocol Address: {}",
            self.proto_addr_family
                .addr_to_string(self.dest_proto_addr.to_vec())
        );

        Result::Ok(())
    }
}
