use core::fmt;

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
    flags: u8,
    fragment_offset: u16,
    ttl: u8,
    proto: u8,
    checksum: u16,
    src_addr: [u8; 4],
    dest_addr: [u8; 4],
    opts: Vec<u8>,
    padding: Vec<u8>,
    payload: Vec<u8>,
}

pub mod pob {

    pub const default_forwarding: u8 = 0;

    pub const expedited_forwarding: u8 = 46;

    pub const voice_admit: u8 = 44;

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
}

pub enum FragmentationFlag {
    FragLast = 0,
    FragMore = 1,
    NoFragLast = 2,
    NoFragMore = 3,
}

pub enum Protocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
}

impl IPv4Packet {
    fn new(
        tos: u8,
        fragmentation: FragmentationFlag,
        fragment_offset: u16,
        protocol: Protocol,
        src_addr: [u8; 4],
        dest_addr: [u8; 4],
        opts: Vec<u8>,
        payload: Vec<u8>,
    ) -> Self {
        let mut packet: Self = Self {
            version: 4,
            ihl: 0, // calc at runtime
            tos: pob::assured_forwarding::AF11,
            total_len: 0,         // calc at runtime
            id: next_packet_id(), // randgen?
            flags: fragmentation as u8,
            fragment_offset: fragment_offset,
            ttl: 128, // recommended defaults are 64 (Linux), 128 (Win), 255 (Net devices)
            proto: protocol as u8,
            checksum: 0,
            src_addr: src_addr,
            dest_addr: dest_addr,
            opts: opts,
            padding: vec![0],
            payload: payload,
        };

        packet.add_padding();
        packet.ihl = packet.calc_header_len();
        packet.total_len = packet.to_bytes().len() as u16;

        return packet;
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.push(self.version);
        bytes.push(self.ihl);
        bytes.push(self.tos);
        bytes.extend_from_slice(&self.total_len.to_be_bytes());
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.fragment_offset.to_be_bytes());
        bytes.push(self.ttl);
        bytes.push(self.proto);
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.src_addr);
        bytes.extend_from_slice(&self.dest_addr);
        bytes.extend_from_slice(&self.opts);
        bytes.extend_from_slice(&self.padding);
        bytes.extend_from_slice(&self.payload);

        return bytes;
    }

    fn calc_header_len(&self) -> u8 {
        let payload_len = self.payload.len();

        let packet_len = self.to_bytes().len();

        let header_len = packet_len - payload_len;

        if header_len < 20 {
            panic!("[Packet][IPv4][Create] IPv4 packet header length is less than minimum 20");
        }

        // Header length is expressed as 32-bit words (4 bytes) and header_len is the length of the
        // header in bytes
        return (header_len / 4) as u8;
    }

    fn add_padding(&mut self) {
        let mut packet_as_bytes = self.to_bytes();

        // IPv4 packet length is measued in 32-bit words, so the total length should be divisible
        // by 4
        if packet_as_bytes.len() % 4 != 0 {
            self.padding.push(0);
            packet_as_bytes = self.to_bytes();
        }
    }
    
    fn calc_checksum(){}
}

impl fmt::Display for IPv4Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TODO")
    }
}
