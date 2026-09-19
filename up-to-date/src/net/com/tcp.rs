use core::fmt;
use std::{
    ops::{BitOr, BitOrAssign},
    sync::LazyLock,
    time::Instant,
};

use crate::net::com::{address::IPv4Address, utils};
use crate::{crypto, net::com::PduPayload};

pub struct Clock(Instant);

impl Clock {
    pub fn new() -> Self {
        Clock(Instant::now())
    }

    pub fn ticks_4_ms(&self) -> u32 {
        let elapsed = self.0.elapsed();
        // TCP specs state that the clock should be incremented every 4 microseconds until it
        // overflows a 32-bit unsigned integer
        // So, we divide the elapsed time in ms by 4, since integer division truncates towards
        // zero (flooring for positives)
        //      0,1,2,3 elapsed -> 0 ticks - 4,5,6,7 elapsed -> 1 tick
        (elapsed.as_micros() / 4) as u32
    }
}

// A LazyLock is a thread safe type that allows a value to be initialized on first access and then
// provides thread-wide read access for the lifetime of the process
static CLOCK: LazyLock<Clock> = LazyLock::new(Clock::new);

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
            write!(f, "Finish ")?;
        }
        if self.contains(Flags::SYN) {
            write!(f, "Synchronize ")?;
        }
        if self.contains(Flags::RST) {
            write!(f, "Reset ")?;
        }
        if self.contains(Flags::PSH) {
            write!(f, "Push ")?;
        }
        if self.contains(Flags::ACK) {
            write!(f, "Acknowledge ")?;
        }
        if self.contains(Flags::URG) {
            write!(f, "Urgent ")?;
        }
        if self.contains(Flags::ECE) {
            write!(f, "ECN Echo ")?;
        }
        if self.contains(Flags::CWR) {
            write!(f, "Congestion Window Reduced ")?;
        }
        if self.contains(Flags::AE) {
            write!(f, "Accurate ECN ")?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    src_port: u16,
    dest_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
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

impl Segment {
    pub const CODEPOINT: u8 = 0x06;
    pub fn new(
        src_ip: IPv4Address,
        src_port: u16,
        dest_ip: IPv4Address,
        dest_port: u16,
        flags: Flags,
        payload: Vec<u8>,
    ) -> Result<Self, SegmentError> {
        let default_hlen = 20;

        Ok(Self {
            src_port: src_port,
            dest_port: dest_port,
            seq_num: 0,
            ack_num: 0,
            hlen: default_hlen,
            flags: flags,
            window: 0,
            checksum: 0,
            urgent_ptr: 0,
            opts: vec![],
            payload: payload,
        }
        .gen_isn(
            &src_ip.addr_bytes(),
            &src_port.to_be_bytes(),
            &dest_ip.addr_bytes(),
            &dest_port.to_be_bytes(),
            crypto::SECRET.bytes(),
        ))
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

    fn gen_isn(
        mut self,
        src_ip: &[u8],
        src_port: &[u8],
        dest_ip: &[u8],
        dest_port: &[u8],
        secret: &[u8],
    ) -> Self {
        // ISN = M + F(src_ip, srp_port, dest_ip, dest_port, secret)
        // M = TCP Clock, +1 every 4ms
        // F = PRF of the connection
        // secret length -> min 128 bits
        // When rotating the secret, ISN space changes so colision could happen. Guard aggainst
        // this

        let mut connection = Vec::new();

        connection.extend_from_slice(src_ip);
        connection.extend_from_slice(src_port);
        connection.extend_from_slice(dest_ip);
        connection.extend_from_slice(dest_port);

        let hash = crypto::hmac::generate::<crypto::sha_256::Sha256>(secret, &connection);
        let hash_bytes = hash.bytes();
        let hash_first_u32 =
            u32::from_be_bytes([hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3]]);

        self.seq_num = CLOCK.ticks_4_ms().wrapping_add(hash_first_u32);
        self
    }

    pub fn checksum(
        mut self,
        src_ip: IPv4Address,
        dest_ip: IPv4Address,
        proto: u8,
    ) -> Result<Self, SegmentError> {
        let mut bytes_for_checksum: Vec<u8> = Vec::new();

        let segment_as_bytes: Vec<u8> =
            Vec::try_from(&self).or_else(|_| Err(SegmentError::InvalidTcpSegment))?;

        // Pseudo-header
        bytes_for_checksum.extend_from_slice(src_ip.addr_bytes());
        bytes_for_checksum.extend_from_slice(dest_ip.addr_bytes());
        bytes_for_checksum.push(0x00);
        bytes_for_checksum.push(proto);
        bytes_for_checksum.extend_from_slice(&(segment_as_bytes.len() as u16).to_be_bytes());

        // Segment Header + Payload
        bytes_for_checksum.extend_from_slice(&segment_as_bytes);

        // Non-transmit padding to make total amount of bytes even if it is odd
        // This is required because checksum is a 2-byte field and thus the calculation iterates
        // the byte array 2 bytes at a time
        if bytes_for_checksum.len() % 2 != 0 {
            bytes_for_checksum.push(0x00);
        }

        let checksum: u16 = utils::calc_checksum(&bytes_for_checksum);

        self.checksum = checksum;

        Ok(self)
    }
}

// TODO: Error handling
pub enum SegmentError {
    InvalidTcpSegment,
    ProtocolMismatch,
}

impl PduPayload for Segment {
    type Payload = Segment;
    type ErrorSpace = SegmentError;
    type CodepointType = u8;

    fn serialize_payload(payload: &Self::Payload) -> Result<Vec<u8>, Self::ErrorSpace> {
        let vec = Vec::try_from(payload).or_else(|_| Err(SegmentError::InvalidTcpSegment))?;
        Ok(vec)
    }

    fn deserialize_payload(
        cp: Self::CodepointType,
        payload: &[u8],
    ) -> Result<Self::Payload, Self::ErrorSpace> {
        if cp != Self::CODEPOINT {
            return Err(SegmentError::ProtocolMismatch);
        }
        let seg = Segment::try_from(payload).or_else(|_| Err(SegmentError::InvalidTcpSegment))?;
        Ok(seg)
    }
    fn codepoint(_payload: &Self::Payload) -> Self::CodepointType {
        Self::CODEPOINT
    }
    fn name() -> String {
        String::from("TCP")
    }
}

impl TryFrom<&Segment> for Vec<u8> {
    type Error = SegmentError;

    fn try_from(segment: &Segment) -> Result<Self, Self::Error> {
        let mut bytes: Vec<u8> = Vec::new();

        // Divide hlen by 4 since header length field is calculated in 32-bit words
        let hlen_and_flags: u16 = ((segment.hlen / 4) as u16) << 12 | segment.flags.bits();

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

        Ok(bytes)
    }
}

impl TryFrom<&[u8]> for Segment {
    type Error = SegmentError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
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

        Ok(segment)
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\nSource Port: {}", self.src_port)?;
        write!(f, "\nDestination Port: {}", self.dest_port)?;
        write!(f, "\nSequence Number: {}", self.seq_num)?;
        write!(f, "\nAcknowledgment Number: {}", self.ack_num)?;
        write!(
            f,
            "\nHeader Length: {} ({} bytes)",
            self.hlen / 4,
            self.hlen
        )?;
        write!(f, "\nFlags: {}", self.flags)?;
        write!(f, "\nWindow: {}", self.window)?;
        write!(f, "\nChecksum: {:X}", self.checksum)?;
        write!(f, "\nUrgent Pointer: {:X}", self.urgent_ptr)?;
        //TODO: Options parser
        write!(f, "\nOptions: {:X?}", self.opts)?;
        // write!(f, "\nPayload: {:X?}", self.payload)?;

        Ok(())
    }
}
