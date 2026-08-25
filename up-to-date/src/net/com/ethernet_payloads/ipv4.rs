use core::fmt;

use crate::net::com::{AddressFamily, ethernet_payloads::utils};

static mut NEXT_ID: u16 = 0;

fn next_datagram_id() -> u16 {
    unsafe {
        NEXT_ID = NEXT_ID.wrapping_add(1);
        NEXT_ID
    }
}
pub struct Datagram {
    version: u8,
    // In the struct, header length will be used as the total byte count instead of the 32-bit word
    // count for simplicity. Convertion will happen when transforming a struct instance into a byte
    // stream and when creating an instance from a byte stream
    hlen: u8,
    tos: u8,
    total_len: u16,
    id: u16,
    flags: FragmentationFlags,
    fragment_offset: u16,
    ttl: u8,
    proto: Protocol,
    checksum: u16,
    src_addr: [u8; 4],
    dest_addr: [u8; 4],
    opts: Vec<u8>,
    payload: Vec<u8>,
}

// DSCP codepoints for Per-Hop Behaviour https://networklessons.com/quality-of-service/ip-precedence-dscp-values
pub mod dscp {
    use crate::net::com::ethernet_payloads::ipv4::dscp;

    // Modern DSCP values
    pub const DEFAULT_FORWARDING: u8 = 0;

    pub const EXPEDITED_FORWARDING: u8 = 46;

    pub const VOICE_ADMIT: u8 = 44;

    // Each class is a different datagram queue and the priority assigned to datagrams in each queue is
    // defined by device/network config
    pub mod assured_forwarding {
        pub const AF11: u8 = 10;
        pub const AF12: u8 = 12;
        pub const AF13: u8 = 14;

        pub const AF21: u8 = 18;
        pub const AF22: u8 = 20;
        pub const AF23: u8 = 22;

        pub const AF31: u8 = 26;
        pub const AF32: u8 = 28;
        pub const AF33: u8 = 30;

        pub const AF41: u8 = 34;
        pub const AF42: u8 = 36;
        pub const AF43: u8 = 38;
    }

    // For compatibility with old IP Precedence Type Of Service model
    pub mod class_selector {
        pub const CS0: u8 = 0;
        pub const CS1: u8 = 8;
        pub const CS2: u8 = 16;
        pub const CS3: u8 = 24;
        pub const CS4: u8 = 32;
        pub const CS5: u8 = 40;
        pub const CS6: u8 = 48;
        pub const CS7: u8 = 56;
    }

    // TODO: Change to impl Display
    pub fn to_string(dscp_value: u8) -> &'static str {
        match dscp_value {
            dscp::DEFAULT_FORWARDING => "Default",
            dscp::EXPEDITED_FORWARDING => "Expedite Forwarding",
            dscp::VOICE_ADMIT => "Voice Admit",
            dscp::assured_forwarding::AF11 => "Assured Forwarding Class 1 Low-Drop",
            dscp::assured_forwarding::AF12 => "Assured Forwarding Class 1 Medium-Drop",
            dscp::assured_forwarding::AF13 => "Assured Forwarding Class 1 High-Drop",
            dscp::assured_forwarding::AF21 => "Assured Forwarding Class 2 Low-Drop",
            dscp::assured_forwarding::AF22 => "Assured Forwarding Class 2 Medium-Drop",
            dscp::assured_forwarding::AF23 => "Assured Forwarding Class 2 High-Drop",
            dscp::assured_forwarding::AF31 => "Assured Forwarding Class 3 Low-Drop",
            dscp::assured_forwarding::AF32 => "Assured Forwarding Class 3 Medium-Drop",
            dscp::assured_forwarding::AF33 => "Assured Forwarding Class 3 High-Drop",
            dscp::assured_forwarding::AF41 => "Assured Forwarding Class 4 Low-Drop",
            dscp::assured_forwarding::AF42 => "Assured Forwarding Class 4 Medium-Drop",
            dscp::assured_forwarding::AF43 => "Assured Forwarding Class 4 High-Drop",
            dscp::class_selector::CS1 => "Class Selector Priority",
            dscp::class_selector::CS2 => "Class Selector Immediate",
            dscp::class_selector::CS3 => "Class Selector Flash",
            dscp::class_selector::CS4 => "Class Selector Flash Override",
            dscp::class_selector::CS5 => "Class Selector Critic/Critical",
            dscp::class_selector::CS6 => "Class Selector Internetwork Control",
            dscp::class_selector::CS7 => "Class Selector Network Control",
            _ => "Unknown DSCP value",
        }
    }
}
#[derive(Clone, Copy)]
pub enum FragmentationFlags {
    FragLast = 0,
    FragMore = 1,
    NoFragLast = 2,
    NoFragMore = 3,
}

impl FragmentationFlags {
    // TODO: Change to impl Display
    pub fn to_string(self) -> &'static str {
        match self {
            FragmentationFlags::FragLast => "Fragmentation Enabled, Last Fragment",
            FragmentationFlags::FragMore => "Fragmentation Enabled, More Fragments",
            FragmentationFlags::NoFragLast | FragmentationFlags::NoFragMore => {
                "Fragmentation Disabled"
            }
        }
    }
}

impl From<u8> for FragmentationFlags {
    fn from(flags: u8) -> Self {
        match flags {
            flags if flags == FragmentationFlags::FragMore as u8 => FragmentationFlags::FragLast,
            flags if flags == FragmentationFlags::FragLast as u8 => FragmentationFlags::FragLast,
            flags if flags == FragmentationFlags::NoFragMore as u8 => {
                FragmentationFlags::NoFragMore
            }
            flags if flags == FragmentationFlags::NoFragLast as u8 => {
                FragmentationFlags::NoFragLast
            }

            _ => panic!("Invalid Fragmentation Flags: {}", flags),
        }
    }
}

// TODO: Move out since it's not specific to IPv4
#[derive(Clone, Copy)]
pub enum Protocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
}

impl Protocol {
    // TODO: Change to impl Display
    pub fn to_string(&self) -> &'static str {
        match self {
            Protocol::ICMP => "ICMP",
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP",
        }
    }
}

impl From<u8> for Protocol {
    fn from(proto: u8) -> Self {
        match proto {
            proto if proto == Protocol::ICMP as u8 => Protocol::ICMP,
            proto if proto == Protocol::TCP as u8 => Protocol::TCP,
            proto if proto == Protocol::UDP as u8 => Protocol::UDP,
            _ => panic!("Unknown protocol: {}", proto),
        }
    }
}

impl Datagram {
    pub fn new(
        protocol: Protocol,
        src_addr: [u8; 4],
        dest_addr: [u8; 4],
        payload: Vec<u8>,
    ) -> Self {
        let default_hlen: u8 = 20;
        let default_total_len: u16 = (default_hlen as usize + payload.len()) as u16;

        let mut datagram: Self = Self {
            version: 4,
            hlen: default_hlen,
            tos: dscp::DEFAULT_FORWARDING,
            total_len: default_total_len,
            id: next_datagram_id(),
            flags: FragmentationFlags::NoFragLast,
            fragment_offset: 0,
            ttl: 128, // recommended defaults are 64 (Linux), 128 (Win), 255 (Net devices)
            proto: protocol,
            checksum: 0,
            src_addr: src_addr,
            dest_addr: dest_addr,
            opts: vec![],
            payload: payload,
        };

        datagram.checksum = utils::calc_checksum(&datagram.to_bytes()[0..default_hlen as usize]);

        return datagram;
    }

    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = tos;
        self
    }

    pub fn flags(mut self, flags: FragmentationFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn fragment_offset(mut self, offset: u16) -> Self {
        self.fragment_offset = offset;
        self
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn opts(mut self, opts: Vec<u8>) -> Self {
        self.opts = opts;

        let post_opts_hlen = self.hlen as usize + self.opts.len();

        let post_padding_hlen = utils::byte_alignment_padding(post_opts_hlen, 4, &mut self.opts);

        self.hlen = post_padding_hlen as u8;
        self.total_len = (post_padding_hlen + self.payload.len()) as u16;
        self.checksum = utils::calc_checksum(&self.to_bytes()[0..post_padding_hlen]);
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        // Tho version and IHl are defined as u8 (because Rust doesn't have a type to accomodate
        // less bits), those fields on a datagram actually share a byte (4 bits each). So, when
        // serializing the datagram object we need to combine the two with a left shift + OR
        bytes.push(self.version << 4 | self.hlen / 4);
        bytes.push(self.tos);
        bytes.extend_from_slice(&self.total_len.to_be_bytes());
        bytes.extend_from_slice(&self.id.to_be_bytes());
        // Same thing as above, but here is a bit more awkward because flags is a 3 bit field while
        // fragment_offset is a 13 bit field and they need to be combined into a 16 bit word
        bytes.extend_from_slice(&((self.flags as u16) << 13 | self.fragment_offset).to_be_bytes());
        bytes.push(self.ttl);
        bytes.push(self.proto as u8);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.src_addr);
        bytes.extend_from_slice(&self.dest_addr);
        bytes.extend_from_slice(&self.opts);
        bytes.extend_from_slice(&self.payload);

        return bytes;
    }
}

impl From<Vec<u8>> for Datagram {
    fn from(buffer: Vec<u8>) -> Self {
        let hlen: u8 = (buffer[0] << 4) >> 4;
        let total_len: u16 = (buffer[2] as u16) << 8 | buffer[3] as u16;
        // Multiply hlen by 4 since header length is meased in 32-bit words (4 bytes)
        // Convert to usize so we can use the result to index buffer
        let payload_offset = (hlen * 4) as usize;

        let mut datagram: Self = Self {
            version: buffer[0] >> 4,
            hlen: hlen * 4,
            tos: buffer[1],
            total_len: total_len,
            id: (buffer[4] as u16) << 8 | buffer[5] as u16,
            flags: FragmentationFlags::from(buffer[6] >> 5), // 3 most significant bits
            fragment_offset: ((buffer[6] << 3) >> 3) as u16 | buffer[7] as u16,
            ttl: buffer[8],
            proto: Protocol::from(buffer[9]),
            checksum: (buffer[10] as u16) << 8 | buffer[11] as u16,
            src_addr: [0, 0, 0, 0],
            dest_addr: [0, 0, 0, 0],
            // TODO: Option parser
            opts: buffer[20..payload_offset].to_vec(),
            payload: buffer[payload_offset..].to_vec(),
        };

        datagram.src_addr.copy_from_slice(&buffer[12..16]);
        datagram.dest_addr.copy_from_slice(&buffer[16..20]);

        datagram
    }
}

impl fmt::Display for Datagram {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        println!("IP Protocol version: {:X}", self.version);
        println!(
            "Datagram Header Length: {:X} ({} bytes)",
            self.hlen / 4,
            self.hlen
        );
        println!("Type Of Service (DSCP): {}", dscp::to_string(self.tos));
        println!("Total Datagram Length: {}", self.total_len);
        println!("ID: {:04X}", self.id);
        println!("Fragmentation Flag: {}", self.flags.to_string());
        println!("Fragment Offset: {:02X}", self.fragment_offset);
        println!("Time To Live: {}", self.ttl);
        println!("Next Level Protocol: {}", self.proto.to_string());
        println!("Checksum: {:04X}", self.checksum);
        println!(
            "Source Address: {}",
            AddressFamily::IPV4.addr_to_string(self.src_addr.to_vec())
        );
        println!(
            "Destination Address: {}",
            AddressFamily::IPV4.addr_to_string(self.dest_addr.to_vec())
        );
        // TODO: Option parser
        println!("Options: {:X?}", self.opts);
        //TODO: Implement after TCP is ready
        // println!("Payload")
        println!("Payload: {:X?}", self.payload);

        Result::Ok(())
    }
}
// TODO: Fragmentation
