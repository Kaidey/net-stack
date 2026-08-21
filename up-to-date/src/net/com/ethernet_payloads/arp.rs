use crate::net::com::AddressFamily;
use core::fmt;

pub struct ArpPacket {
    hardware_addr: AddressFamily,
    proto_addr: AddressFamily,
    pub op: u16,
    pub src_hardware_addr: [u8; 6],
    pub src_proto_addr: [u8; 4],
    pub dest_hardware_addr: [u8; 6],
    pub dest_proto_addr: [u8; 4],
    padding: Vec<u8>,
}

impl ArpPacket {
    pub fn new_request(
        hardware_addr: AddressFamily,
        proto_addr: AddressFamily,
        src_hardware_addr: [u8; 6],
        src_proto_addr: [u8; 4],
        dest_hardware_addr: [u8; 6],
        dest_proto_addr: [u8; 4],
    ) -> Self {
        let mut packet = Self {
            hardware_addr: hardware_addr,
            proto_addr: proto_addr,
            op: 0x0001,
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

        bytes.extend_from_slice(&self.hardware_addr.family.to_be_bytes());
        bytes.extend_from_slice(&self.proto_addr.family.to_be_bytes());
        bytes.push(self.hardware_addr.len);
        bytes.push(self.proto_addr.len);
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

        while packet_as_bytes.len() < 40 {
            self.padding.push(0);
            packet_as_bytes = self.to_bytes();
        }
    }
}
impl From<Vec<u8>> for ArpPacket {
    fn from(buffer: Vec<u8>) -> Self {
        let mut packet = Self {
            // Combines the first 2 u8 of buffer into a u16 by casting the first u8 to u16 and then
            // shifting it 8 bits left. Finally, performs an OR with the second u8
            hardware_addr: AddressFamily::from_family(((buffer[0] as u16) << 8) | buffer[1] as u16).unwrap(), 
            proto_addr: AddressFamily::from_family(((buffer[2] as u16) << 8) | buffer[3] as u16).unwrap(),
            op: (buffer[6] as u16) << 8 | buffer[7] as u16,
            src_hardware_addr: [0,0,0,0,0,0],
            src_proto_addr: [0,0,0,0],
            dest_hardware_addr: [0,0,0,0,0,0],
            dest_proto_addr: [0,0,0,0],
            padding: buffer[28..].to_vec(),
        };

        packet.src_hardware_addr.copy_from_slice(&buffer[8..14]);
        packet.src_proto_addr.copy_from_slice(&buffer[14..18]);
        packet.dest_hardware_addr.copy_from_slice(&buffer[18..24]);
        packet.dest_proto_addr.copy_from_slice(&buffer[24..28]);

        packet
    }
}
impl fmt::Display for ArpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        println!(
            "Hardware Address Type: {:04?} ({})",
            self.hardware_addr.family,
            AddressFamily::name(&self.hardware_addr)
        );
        println!(
            "Protocol Address Type: {:04X?} ({})",
            self.proto_addr.family,
            AddressFamily::name(&self.proto_addr)
        );
        println!("Hardware Address Length: {:02X?}", self.hardware_addr.len);
        println!("Protocol Address Length: {:02X?}", self.proto_addr.len);

        match self.op {
            0x0001 => println!("Operation: {:04?} ({})", self.op, "Request"),
            0x0002 => println!("Operation: {:04?} ({})", self.op, "Reply"),
            _ => println!("Unknown Operation"),
        }

        println!(
            "Source Hardware Address: {}",
            AddressFamily::to_string(&self.hardware_addr, self.src_hardware_addr.to_vec())
        );
        println!(
            "Source Protocol Address: {}",
            AddressFamily::to_string(&self.proto_addr, self.src_proto_addr.to_vec())
        );
        println!(
            "Destination Hardware Address: {}",
            AddressFamily::to_string(&self.hardware_addr, self.dest_hardware_addr.to_vec())
        );
        println!(
            "Destination Protocol Address: {}",
            AddressFamily::to_string(&self.proto_addr, self.dest_proto_addr.to_vec())
        );

        Result::Ok(())
    }
}
