use core::fmt;
use std::ops::{BitOr, BitOrAssign};

use crate::net::com::{
    AddressFamily,
    ethernet_payloads::{tcp, utils},
};

// TODO: Review. This might be a problem for multi-thread
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
    hlen: usize,
    dscp: Dscp,
    // TODO: Understand and impl
    ecn: u8,
    total_len: usize,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dscp(u8);

impl Dscp {
    // Modern DSCP values
    pub const DEFAULT: Self = Self(0x00);

    pub const EXPEDITED_FORWARDING: Self = Self(0x2E);

    pub const VOICE_ADMIT: Self = Self(0x2C);

    // Each class (first digit) is a different datagram queue and the priority assigned to datagrams in each queue is
    // defined by device/network config
    pub const AF11: Self = Self(0x0A);
    pub const AF12: Self = Self(0x0C);
    pub const AF13: Self = Self(0x0E);

    pub const AF21: Self = Self(0x12);
    pub const AF22: Self = Self(0x14);
    pub const AF23: Self = Self(0x16);

    pub const AF31: Self = Self(0x1A);
    pub const AF32: Self = Self(0x1C);
    pub const AF33: Self = Self(0x1E);

    pub const AF41: Self = Self(0x22);
    pub const AF42: Self = Self(0x24);
    pub const AF43: Self = Self(0x26);

    // For compatibility with old IP Precedence Type Of Service model
    pub const CS1: Self = Self(0x08);
    pub const CS2: Self = Self(0x10);
    pub const CS3: Self = Self(0x18);
    pub const CS4: Self = Self(0x20);
    pub const CS5: Self = Self(0x28);
    pub const CS6: Self = Self(0x30);
    pub const CS7: Self = Self(0x38);

    pub fn bits(self) -> u8 {
        self.0
    }
}

impl From<u8> for Dscp {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<Dscp> for u8 {
    fn from(dscp: Dscp) -> u8 {
        dscp.0
    }
}

impl fmt::Display for Dscp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Dscp::DEFAULT => write!(f, "Default"),
            Dscp::EXPEDITED_FORWARDING => write!(f, "Expedite Forwarding"),
            Dscp::VOICE_ADMIT => write!(f, "Voice Admit"),
            Dscp::AF11 => write!(f, "Assured Forwarding Class 1 Low-Drop"),
            Dscp::AF12 => write!(f, "Assured Forwarding Class 1 Medium-Drop"),
            Dscp::AF13 => write!(f, "Assured Forwarding Class 1 High-Drop"),
            Dscp::AF21 => write!(f, "Assured Forwarding Class 2 Low-Drop"),
            Dscp::AF22 => write!(f, "Assured Forwarding Class 2 Medium-Drop"),
            Dscp::AF23 => write!(f, "Assured Forwarding Class 2 High-Drop"),
            Dscp::AF31 => write!(f, "Assured Forwarding Class 3 Low-Drop"),
            Dscp::AF32 => write!(f, "Assured Forwarding Class 3 Medium-Drop"),
            Dscp::AF33 => write!(f, "Assured Forwarding Class 3 High-Drop"),
            Dscp::AF41 => write!(f, "Assured Forwarding Class 4 Low-Drop"),
            Dscp::AF42 => write!(f, "Assured Forwarding Class 4 Medium-Drop"),
            Dscp::AF43 => write!(f, "Assured Forwarding Class 4 High-Drop"),
            Dscp::CS1 => write!(f, "Class Selector Priority"),
            Dscp::CS2 => write!(f, "Class Selector Immediate"),
            Dscp::CS3 => write!(f, "Class Selector Flash"),
            Dscp::CS4 => write!(f, "Class Selector Flash Override"),
            Dscp::CS5 => write!(f, "Class Selector Critic/Critical"),
            Dscp::CS6 => write!(f, "Class Selector Internetwork Control"),
            Dscp::CS7 => write!(f, "Class Selector Network Control"),
            _ => write!(f, "Unknown DSCP value"),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentationFlags(u8);

impl FragmentationFlags {
    pub const LAST_FRAGMENT: Self = Self(0x0);
    pub const MORE_FRAGMENTS: Self = Self(0x1);
    pub const DONT_FRAGMENT: Self = Self(0x2);
    pub const DONT_FRAGMEMT_MORE: Self = Self(0x3);

    pub fn bits(self) -> u8 {
        self.0
    }
}

impl fmt::Display for FragmentationFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            FragmentationFlags::LAST_FRAGMENT => write!(f, "Fragmentation Enabled, Last Fragment"),
            FragmentationFlags::MORE_FRAGMENTS => {
                write!(f, "Fragmentation Enabled, More Fragments")
            }
            FragmentationFlags::DONT_FRAGMENT | FragmentationFlags::DONT_FRAGMEMT_MORE => {
                write!(f, "Fragmentation Disabled")
            }
            _ => write!(f, "Unknown Fragmentation Flag"),
        }
    }
}

impl From<u8> for FragmentationFlags {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<FragmentationFlags> for u8 {
    fn from(flags: FragmentationFlags) -> Self {
        flags.0
    }
}

// TODO: Move out since it's not specific to IPv4
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protocol(u8);

impl Protocol {
    pub const ICMP: Self = Self(0x01);
    pub const TCP: Self = Self(0x06);
    pub const UDP: Self = Self(0x11);

    pub fn bits(self) -> u8 {
        self.0
    }
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<Protocol> for u8 {
    fn from(protocol: Protocol) -> u8 {
        protocol.0
    }
}
impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            _ => write!(f, "Unknown Protocol"),
        }
    }
}

#[derive(Debug)]
pub enum DatagramError {
    PayloadTooLarge,
    HeaderTooLarge,
}

impl Datagram {
    pub fn new(
        protocol: Protocol,
        src_addr: [u8; 4],
        dest_addr: [u8; 4],
        payload: Vec<u8>,
    ) -> Result<Self, DatagramError> {
        let default_hlen: usize = 20;
        let total_len: usize = default_hlen + payload.len();

        if total_len > u16::MAX as usize {
            return Err(DatagramError::PayloadTooLarge);
        }

        Ok(Self {
            version: 4,
            hlen: default_hlen,
            dscp: Dscp::DEFAULT,
            ecn: 0,
            total_len: total_len,
            id: next_datagram_id(),
            flags: FragmentationFlags::DONT_FRAGMENT,
            fragment_offset: 0,
            ttl: 128, // recommended defaults are 64 (Linux), 128 (Win), 255 (Net devices)
            proto: protocol,
            checksum: 0,
            src_addr: src_addr,
            dest_addr: dest_addr,
            opts: vec![],
            payload: payload,
        })
    }

    pub fn dscp(mut self, dscp: Dscp) -> Self {
        self.dscp = dscp;
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

    pub fn opts(mut self, opts: Vec<u8>) -> Result<Self, DatagramError> {
        self.opts = opts;

        let post_opts_hlen = self.hlen + self.opts.len();

        let post_padding_hlen = utils::byte_alignment_padding(post_opts_hlen, 4, &mut self.opts);

        // Header length is a 4 bit field so max value for the field is 15 -> 15 * 4 = 60 bytes
        if post_padding_hlen > 60 {
            return Err(DatagramError::HeaderTooLarge);
        }

        self.hlen = post_padding_hlen;
        self.total_len = post_padding_hlen + self.payload.len();
        Ok(self)
    }

    pub fn checksum(mut self) -> Self {

        let datagram_as_bytes: Vec<u8> = Vec::from(&self);

        let checksum: u16 = utils::calc_checksum(&datagram_as_bytes[..self.hlen]);

        self.checksum = checksum;

        self
    }
}

// No need to consume the Datagram instance for serialization, so we impl for borrow
impl From<&Datagram> for Vec<u8> {
    fn from(datagram: &Datagram) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.push(datagram.version << 4 | (datagram.hlen / 4) as u8);
        bytes.push(datagram.dscp.bits() << 2 | datagram.ecn);
        bytes.extend_from_slice(&(datagram.total_len as u16).to_be_bytes());
        bytes.extend_from_slice(&datagram.id.to_be_bytes());
        bytes.extend_from_slice(
            &((datagram.flags.bits() as u16) << 13 | datagram.fragment_offset).to_be_bytes(),
        );
        bytes.push(datagram.ttl);
        bytes.push(datagram.proto.bits() as u8);
        bytes.extend_from_slice(&datagram.checksum.to_be_bytes());
        bytes.extend_from_slice(&datagram.src_addr);
        bytes.extend_from_slice(&datagram.dest_addr);
        bytes.extend_from_slice(&datagram.opts);
        bytes.extend_from_slice(&datagram.payload);

        bytes
    }
}

impl From<&[u8]> for Datagram {
    fn from(buffer: &[u8]) -> Self {
        let hlen_in_32bit_words: usize = (buffer[0] & 0x0F) as usize;
        let hlen_in_bytes: usize = hlen_in_32bit_words * 4;
        let total_len: usize = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;

        let mut datagram: Self = Self {
            version: buffer[0] >> 4,
            hlen: hlen_in_bytes,
            dscp: Dscp(buffer[1] >> 2),
            ecn: buffer[1] & 0x03,
            total_len: total_len,
            id: u16::from_be_bytes([buffer[4], buffer[5]]),
            flags: FragmentationFlags::from(buffer[6] >> 5), // 3 most significant bits
            fragment_offset: u16::from_be_bytes([buffer[6] & 0x1F, buffer[7]]),
            ttl: buffer[8],
            proto: Protocol::from(buffer[9]),
            checksum: u16::from_be_bytes([buffer[10], buffer[11]]),
            src_addr: [0, 0, 0, 0],
            dest_addr: [0, 0, 0, 0],
            // TODO: Option parser
            opts: buffer[20..hlen_in_bytes].to_vec(),
            payload: buffer[hlen_in_bytes..].to_vec(),
        };

        datagram.src_addr.copy_from_slice(&buffer[12..16]);
        datagram.dest_addr.copy_from_slice(&buffer[16..20]);

        datagram
    }
}

impl fmt::Display for Datagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\nIP Protocol version: {}", self.version)?;
        write!(
            f,
            "\nDatagram Header Length: {} ({} bytes)",
            self.hlen / 4,
            self.hlen
        )?;
        write!(f, "\nType Of Service (DSCP): {}", self.dscp)?;
        write!(f, "\nTotal Datagram Length: {}", self.total_len)?;
        write!(f, "\nID: {:04X}", self.id)?;
        write!(f, "\nFragmentation Flag: {}", self.flags)?;
        write!(f, "\nFragment Offset: {:02X}", self.fragment_offset)?;
        write!(f, "\nTime To Live: {}", self.ttl)?;
        write!(f, "\nNext Level Protocol: {}", self.proto)?;
        write!(f, "\nChecksum: {:04X}", self.checksum)?;
        write!(
            f,
            "\nSource Address: {}",
            AddressFamily::IPV4.addr_to_string(self.src_addr.to_vec())
        )?;
        write!(
            f,
            "\nDestination Address: {}",
            AddressFamily::IPV4.addr_to_string(self.dest_addr.to_vec())
        )?;
        // TODO: Option parser
        write!(f, "\nOptions: {:X?}", self.opts)?;

        match self.proto {
            Protocol::TCP => write!(
                f,
                "\nPayload ({}): {}",
                self.proto,
                tcp::Segment::from(self.payload.as_slice())
            )?,
            Protocol::ICMP => write!(f, "\nPayload ({}): NotImpl", self.proto)?,
            Protocol::UDP => write!(f, "\nPayload ({}): NotImpl", self.proto)?,
            _ => write!(f, "\nPayload ({}): {:X?}", self.proto, self.payload)?,
        }

        Ok(())
    }
}
// TODO: Fragmentation
