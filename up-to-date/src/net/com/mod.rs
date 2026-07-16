use core::fmt;

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

pub struct FrameType;

impl FrameType {
    pub const ARP: u16 = 0x0806;
}

pub struct Address {
    addr_type: u16,
    addr_len: u8,
}

pub struct ArpAddressTypes;

impl ArpAddressTypes {
    pub const ETHERNET: Address = Address {
        addr_type: 1,
        addr_len: 6,
    };
    pub const IPV4: Address = Address {
        addr_type: 2048,
        addr_len: 4,
    };
}

struct ArpOperations;

impl ArpOperations {
    pub const REQUEST: u16 = 1;
    pub const REPLY: u16 = 2;
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
            op: ArpOperations::REQUEST,
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

impl fmt::Display for ArpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.to_bytes() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}
