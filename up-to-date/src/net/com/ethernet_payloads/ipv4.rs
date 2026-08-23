use core::fmt;

use crate::net::com::AddressFamily;

static mut NEXT_ID: u16 = 0;

fn next_packet_id() -> u16 {
    unsafe {
        NEXT_ID = NEXT_ID.wrapping_add(1);
        NEXT_ID
    }
}
pub struct IPv4Packet {
    version: u8,
    ihl: u8,
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
    padding: Vec<u8>,
    payload: Vec<u8>,
}

// DSCP codepoints for Per-Hop Behaviour https://networklessons.com/quality-of-service/ip-precedence-dscp-values
pub mod dscp {
    use crate::net::com::ethernet_payloads::ipv4::dscp;

    // Modern DSCP values
    pub const DEFAULT_FORWARDING: u8 = 0;

    pub const EXPEDITED_FORWARDING: u8 = 46;

    pub const VOICE_ADMIT: u8 = 44;

    // Each class is a different packet queue and the priority assigned to packets in each queue is
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
// TODO: Move out since it's not specific to IPv4
#[derive(Clone, Copy)]
pub enum Protocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
}

impl Protocol{
    pub fn to_string(&self) -> &'static str{
        match self{
            Protocol::ICMP => "ICMP",
            Protocol::TCP => "TCP",
            Protocol::UDP => "UDP"
        }
    }
}

impl IPv4Packet {
    pub fn new(
        protocol: Protocol,
        src_addr: [u8; 4],
        dest_addr: [u8; 4],
        payload: Vec<u8>,
    ) -> Self {
        let mut packet: Self = Self {
            version: 4,
            ihl: 0,
            tos: dscp::DEFAULT_FORWARDING,
            total_len: 0,
            id: next_packet_id(),
            flags: FragmentationFlags::NoFragLast,
            fragment_offset: 0,
            ttl: 128, // recommended defaults are 64 (Linux), 128 (Win), 255 (Net devices)
            proto: protocol,
            checksum: 0,
            src_addr: src_addr,
            dest_addr: dest_addr,
            opts: vec![],
            padding: vec![],
            payload: payload,
        };

        packet.calc_padding();
        packet.calc_header_len();
        packet.total_len = packet.to_bytes().len() as u16;
        packet.calc_checksum();

        return packet;
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
        // Since opts is a Vec<u8> it can hold any number of bytes, so we need to recalculate
        // padding for the packet header
        self.calc_padding();
        self.calc_header_len();
        self.total_len = self.to_bytes().len() as u16;
        self.calc_checksum();
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        // Tho version and IHl are defined as u8 (because Rust doesn't have a type to accomodate
        // less bits), those fields on a packet actually share a byte (4 bits each). So, when
        // serializing the packet object we need to combine the two with a left shift + OR
        bytes.push(self.version << 4 | self.ihl);
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
        bytes.extend_from_slice(&self.padding);
        bytes.extend_from_slice(&self.payload);

        return bytes;
    }

    fn calc_header_len(&mut self) {
        let payload_len = self.payload.len();

        let packet_len = self.to_bytes().len();

        let header_len = packet_len - payload_len;

        if header_len < 20 {
            panic!("[Packet][IPv4][Create] IPv4 packet header length is less than minimum 20");
        }

        // Header length is expressed as 32-bit words (4 bytes) and header_len is the length of the
        // header in bytes
        self.ihl = (header_len / 4) as u8;
    }

    fn calc_padding(&mut self) {
        let payload_len = self.payload.len();

        let mut packet_len = self.to_bytes().len();

        let mut header_len = packet_len - payload_len;
        // IPv4 packet length is measured in 32-bit words, so the total length should be divisible
        // by 4
        while header_len % 4 != 0 {
            self.padding.push(0);
            packet_len = self.to_bytes().len();
            header_len = packet_len - payload_len;
        }
    }

    fn calc_checksum(&mut self) {
        let packet_header_bytes: Vec<u8> = self.to_bytes();
        let mut count = 0;
        let mut sum: u32 = 0;

        // Calculate sum of every 16 bit word on the packet header
        while count < packet_header_bytes.len() {
            // Combine 2 bytes into a 16 bit word
            let next_16bit_word =
                ((packet_header_bytes[count] as u16) << 8) | packet_header_bytes[count + 1] as u16;

            sum = sum + next_16bit_word as u32;
            count = count + 2;
        }

        // Checksum needs to be a 16 bit word, so, if the final sum is more than 16 bits, we
        // remove the extra bits (most significant) and add them onto the checksum word (16
        // least significant bits)

        // 16-bit right shift to extract extra bits
        //
        // E.g: sum = 2D130 -> extra_bits = 2
        let extra_bits = sum >> 16;

        // 16-bit left shift to discard most significant extra bits followed by 16-bit right shift
        // to restore the original least significant 16-bit word
        //
        // E.g: sum = 2D130 -> sum_ls16bit = D130
        let sum_ls16bit = (sum << 16) >> 16;

        // Add the extra bits to the least significant 16 bits of the final sum
        // and calculate the 1's complement of the resulting value (flipping all bits) using XOR
        self.checksum = ((sum_ls16bit + extra_bits) ^ 0xFFFF)
            .try_into()
            .expect("Checksum is greater than 16 bits");
    }
}

impl fmt::Display for IPv4Packet {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        println!("IP Protocol version: {:X}", self.version);
        println!(
            "Packet Header Length: {:X} ({} bytes)",
            self.ihl,
            self.ihl * 4
        );
        println!("Type Of Service (DSCP): {}", dscp::to_string(self.tos));
        println!("ID: {:04X}", self.id);
        println!("Fragmentation Flag: {}", self.flags.to_string());
        println!("Fragment Offset: {:02X}", self.fragment_offset);
        println!("Time To Live: {}", self.ttl);
        println!("Next Level Protocol: {}", self.proto.to_string());
        println!("Checksum: {:04X}", self.checksum);
        println!("Source Address: {}", AddressFamily::IPV4.addr_to_string(self.src_addr.to_vec()));
        println!("Destination Address: {}", AddressFamily::IPV4.addr_to_string(self.dest_addr.to_vec()));
        println!("Options: {:X?}", self.opts);
        //TODO: Implement after TCP is ready
        // println!("Payload")

        Result::Ok(())
    }
}
