use crate::net::com::ethernet_payloads::utils;
use core::fmt;
use std::ops::{BitOr, BitOrAssign};

pub struct Segment {
    src_port: u16,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
    // In the struct, header length will be used as the total byte count instead of the 32-bit word
    // count for simplicity. Convertion will happen when transforming a struct instance into a byte
    // stream and when creating an instance from a byte stream
    hlen: usize,
    flags: Flags,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
    opts: Vec<u8>,
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Tuple struct. It has one unnamed field of type u16
pub struct Flags(u16);

impl Flags {
    pub const FIN: Self = Self(0x001);
    pub const SYN: Self = Self(0x002);
    pub const RST: Self = Self(0x004);
    pub const PSH: Self = Self(0x008);
    pub const ACK: Self = Self(0x010);
    pub const URG: Self = Self(0x020);
    pub const ECE: Self = Self(0x040);
    pub const CWR: Self = Self(0x080);
    pub const AE: Self = Self(0x100);

    pub fn bits(self) -> u16 {
        // This returns the value of the unnamed field of self. If the tuple struct was
        // Flags(u16,u16), fields would be self.0 and self.1
        self.0
    }

    // Bin number B is contained in bin number A if the logical AND between them equals B
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.contains(Flags::FIN) {
            write!(f, "Finish ");
        }
        if self.contains(Flags::SYN) {
            write!(f, "Synchronize ");
        }
        if self.contains(Flags::RST) {
            write!(f, "Reset ");
        }
        if self.contains(Flags::PSH) {
            write!(f, "Push ");
        }
        if self.contains(Flags::ACK) {
            write!(f, "Acknowledge ");
        }
        if self.contains(Flags::URG) {
            write!(f, "Urgent ");
        }
        if self.contains(Flags::ECE) {
            write!(f, "ECN Echo ");
        }
        if self.contains(Flags::CWR) {
            write!(f, "Congestion Window Reduced ");
        }
        if self.contains(Flags::AE) {
            write!(f, "Accurate ECN ");
        }

        Result::Ok(())
    }
}

impl From<u16> for Flags {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Flags> for u16 {
    fn from(flags: Flags) -> Self {
        flags.0
    }
}

// Allows "|" syntax between multiple instances of Flags
// An argument could be made to implement a function for this like we did for contains(), but it
// would actually make for worse usability/readability if we need to create an instance of Flags with multiple
// flags enabled
//
// let flags = Flags::SYN.add(Flags::FIN).add(Flags::URG)
// vs
// let flags = Flags::SYN | Flags::FIN | Flags::URG
//
// For contains however, it is more useful to implement the function than to implement BitAnd since
// there is the extra step of asserting the result of the AND against the flag we wish to check
impl BitOr for Flags {
    type Output = Self;

    // rhs = right-hand side (of the OR operation)
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// Allows "|=" syntax (OR and assign) like +=
impl BitOrAssign for Flags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

impl Segment {
    pub fn new(src_port: u16, dest_port: u16, flags: Flags, payload: Vec<u8>) -> Self {
        let default_hlen = 20;

        Self {
            src_port: src_port,
            dest_port: dest_port,
            seq_num: Self::gen_seq_num(),
            ack_num: 0,
            hlen: default_hlen,
            flags: flags,
            window: 0,
            checksum: 0,
            urgent_ptr: 0,
            opts: vec![],
            payload: payload,
        }
    }

    pub fn ack(mut self, ack_num: u32) -> Self {
        self.ack_num = ack_num;
        self
    }

    pub fn seq(mut self, seq_num: u32) -> Self {
        self.seq_num = seq_num;
        self
    }

    pub fn opts(mut self, opts: Vec<u8>) -> Self {
        self.opts = opts;

        let post_opts_hlen = self.hlen + self.opts.len();

        let post_padding_hlen = utils::byte_alignment_padding(post_opts_hlen, 4, &mut self.opts);

        if post_padding_hlen > 60 {
            panic!("[TCP][Segment][AddOpts] TCP segment header length is more than maximum 60");
        }

        self.hlen = post_padding_hlen;
        self
    }

    // Generate the Initial Sequence Number
    // TODO
    fn gen_seq_num() -> u32 {
        0
    }
}

impl From<Segment> for Vec<u8> {
    fn from(segment: Segment) -> Self {
        let mut bytes: Vec<u8> = Vec::new();

        // Divide hlen by 4 since header length field is calculated in 32-bit words
        let hlen_and_flags: u16 = ((segment.hlen / 4) as u16) << 12 | segment.flags.bits();

        // TODO: Calc Checksum here only

        bytes.extend_from_slice(&segment.src_port.to_be_bytes());
        bytes.extend_from_slice(&segment.dest_port.to_be_bytes());
        bytes.extend_from_slice(&segment.seq_num.to_be_bytes());
        bytes.extend_from_slice(&segment.ack_num.to_be_bytes());
        bytes.extend_from_slice(&hlen_and_flags.to_be_bytes());
        bytes.extend_from_slice(&segment.window.to_be_bytes());
        bytes.extend_from_slice(&segment.checksum.to_be_bytes());
        bytes.extend_from_slice(&segment.urgent_ptr.to_be_bytes());
        bytes.extend_from_slice(&segment.opts);
        bytes.extend_from_slice(&segment.payload);

        bytes
    }
}

impl From<&[u8]> for Segment {
    fn from(buffer: &[u8]) -> Self {
        let hlen_rsv_flags_word: u16 = u16::from_be_bytes([buffer[12], buffer[13]]);

        let hlen_in_32bit_words: usize = (hlen_rsv_flags_word >> 12) as usize;
        let hlen_in_bytes: usize = hlen_in_32bit_words * 4;
        // Keep only 1st bit of 1st byte and all bits of second byte
        let flags: u16 = hlen_rsv_flags_word & 0x01FF;

        let segment: Self = Self {
            src_port: u16::from_be_bytes([buffer[0], buffer[1]]),
            dest_port: u16::from_be_bytes([buffer[2], buffer[3]]),
            seq_num: u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
            ack_num: u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]),
            hlen: hlen_in_bytes,
            flags: Flags(flags),
            window: u16::from_be_bytes([buffer[14], buffer[15]]),
            checksum: u16::from_be_bytes([buffer[16], buffer[17]]),
            urgent_ptr: u16::from_be_bytes([buffer[18], buffer[19]]),
            opts: buffer[20..hlen_in_bytes].to_vec(),
            payload: buffer[hlen_in_bytes..].to_vec(),
        };

        segment
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\nSource Port: {}", self.src_port);
        write!(f, "\nDestination Port: {}", self.dest_port);
        write!(f, "\nSequence Number: {}", self.seq_num);
        write!(f, "\nAcknowledgment Number: {}", self.ack_num);
        write!(
            f,
            "\nHeader Length: {} ({} bytes)",
            self.hlen / 4,
            self.hlen
        );
        write!(f, "\nFlags: {}", self.flags);
        write!(f, "\nWindow: {}", self.window);
        write!(f, "\nChecksum: {:X}", self.checksum);
        write!(f, "\nUrgent Pointer: {:X}", self.urgent_ptr);
        //TODO: Options parser
        write!(f, "\nOptions: {:X?}", self.opts);
        write!(f, "\nPayload: {:X?}", self.payload);

        Ok(())
    }
}
