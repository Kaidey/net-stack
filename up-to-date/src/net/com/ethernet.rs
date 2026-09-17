use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// In the case of enums, Debug allows us to use the format specifier {:?} to print the variant
// labels
pub enum EtherType {
    IPv4,
    IPv6,
    Arp,
    Length(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IPv4,
            0x0806 => EtherType::Arp,
            0x86DD => EtherType::IPv6,
            // Values up to 1500 are valid lengths, since 1500 bytes is the MTU for ethernet
            // Only values above 1536 (inclusive) are mapped to EhterTypes and 1501-1535 is unused
            v if v <= 1500 => EtherType::Length(v),
            _ => panic!("Unknown/invalid EtherType of length"),
        }
    }
}

impl From<&EtherType> for u16 {
    fn from(variant: &EtherType) -> u16 {
        match *variant {
            EtherType::IPv4 => 0x0800,
            EtherType::Arp => 0x0806,
            EtherType::IPv6 => 0x86DD,
            // This syntax is called destructuring, in this case for enums https://google.github.io/comprehensive-rust/pattern-matching/destructuring-enums.html
            // If 'variant' is EtherType::Length, the u16 value held by the variant will be bound to 'len'
            EtherType::Length(len) => len,
        }
    }
}

pub struct EthernetFrame {
    dest_mac_address: [u8; 6],
    src_mac_address: [u8; 6],
    // Type or length of the payload
    type_or_length: EtherType,
    payload: Vec<u8>,
}

impl EthernetFrame {
    pub fn new(
        dest_mac_address: [u8; 6],
        src_mac_address: [u8; 6],
        type_or_length: EtherType,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            dest_mac_address: dest_mac_address,
            src_mac_address: src_mac_address,
            type_or_length: type_or_length,
            payload: payload,
        }
    }
}

impl From<&EthernetFrame> for Vec<u8> {
    fn from(value: &EthernetFrame) -> Self {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&value.dest_mac_address);
        bytes.extend_from_slice(&value.src_mac_address);
        bytes.extend_from_slice(&u16::from(&value.type_or_length).to_be_bytes());
        bytes.extend_from_slice(&value.payload);

        bytes
    }
}

impl From<&[u8]> for EthernetFrame {
    fn from(buffer: &[u8]) -> Self {
        let mut eth_frame = Self {
            dest_mac_address: [0, 0, 0, 0, 0, 0],
            src_mac_address: [0, 0, 0, 0, 0, 0],
            type_or_length: EtherType::from(u16::from_be_bytes([buffer[12], buffer[13]])),
            payload: buffer[14..].to_vec(),
        };

        eth_frame.dest_mac_address.copy_from_slice(&buffer[0..6]);
        eth_frame.src_mac_address.copy_from_slice(&buffer[6..12]);

        eth_frame
    }
}

// impl fmt::Display for EthernetFrame {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let mut serialized_payload: Option<PacketType> = None;
//
//         // TODO: Review
//         for frame_type in FrameType::variations_as_vec().iter() {
//             if frame_type.hex_value() == self.type_or_length {
//                 serialized_payload = FrameType::serialize_payload(frame_type, self.payload.clone()) //frame_type.serialize_payload(self.payload.clone());
//             }
//         }
//
//         println!(
//             "\nDestination MAC: {}",
//             AddressFamily::MAC.addr_to_string(self.dest_mac_address.to_vec())
//         );
//         println!(
//             "Source MAC: {}",
//             AddressFamily::MAC.addr_to_string(self.src_mac_address.to_vec())
//         );
//         println!(
//             "Frame Type/Length: {:04X?} ({})",
//             self.type_or_length,
//             FrameType::name_from_u16(self.type_or_length)
//         );
//
//         match serialized_payload {
//             Some(PacketType::Arp(arp)) => println!("{}", arp),
//             Some(PacketType::IPv4(ipv4)) => println!("{}", ipv4),
//             Some(PacketType::IPv6(ipv6)) => println!("{}", ipv6),
//             None => println!("Unknown payload type"),
//         }
//
//         fmt::Result::Ok(())
//     }
// }
