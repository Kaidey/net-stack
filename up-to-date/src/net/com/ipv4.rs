use core::fmt;

use crate::net::com::{
    PduPayload,
    address::{AddressError, IPv4Address},
    tcp, utils,
};

// TODO: Review. This might be a problem for multi-thread
static mut NEXT_ID: u16 = 0;

fn next_datagram_id() -> u16 {
    unsafe {
        NEXT_ID = NEXT_ID.wrapping_add(1);
        NEXT_ID
    }
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

#[derive(Debug)]
pub enum DatagramError {
    PayloadTooLarge,
    HeaderTooLarge,
    UnknownProtocol,
    AddressParsingFailed,
    PayloadWrong,
    DatagramWrong,
    ProtocolMismatch,
}

impl From<AddressError> for DatagramError {
    fn from(err: AddressError) -> Self {
        match err {
            AddressError::NotEnoughOctets => DatagramError::AddressParsingFailed,
            AddressError::ConvertionFailed => DatagramError::AddressParsingFailed
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IPv4Payload {
    Tcp(Datagram<tcp::Segment>),
    // Udp(Datagram<udp::Segment>),
    Unknown(Datagram<UnknownPayload>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPayload(u8, Vec<u8>);

impl PduPayload for UnknownPayload {
    type Payload = UnknownPayload;
    type ErrorSpace = DatagramError;
    type CodepointType = u8;

    fn serialize_payload(payload: &Self::Payload) -> Result<Vec<u8>, Self::ErrorSpace> {
        Ok((*payload).1.to_vec())
    }
    fn deserialize_payload(
        cp: Self::CodepointType,
        payload: &[u8],
    ) -> Result<Self::Payload, Self::ErrorSpace> {
        Ok(UnknownPayload(cp, payload.to_vec()))
    }
    fn codepoint(payload: &Self::Payload) -> Self::CodepointType {
        payload.0
    }
    fn name() -> String {
        String::from("")
    }
}

impl fmt::Display for UnknownPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Codepoint: {:02X}", self.0)?;
        write!(f, "Payload: {:?}", self.1)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram<P>
where
    P: PduPayload,
{
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
    checksum: u16,
    src_addr: IPv4Address,
    dest_addr: IPv4Address,
    opts: Vec<u8>,
    pub payload: P::Payload,
}

impl<P: PduPayload<CodepointType = u8>> Datagram<P> {
    pub const CODEPOINT: u16 = 0x0800;

    pub fn new(
        src_ip: IPv4Address,
        dest_ip: IPv4Address,
        payload: P::Payload,
    ) -> Result<Self, DatagramError> {
        let default_hlen: usize = 20;
        let payload_len = P::serialize_payload(&payload)
            .or_else(|_| Err(DatagramError::PayloadWrong))?
            .len();
        let total_len: usize = default_hlen + payload_len;

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
            checksum: 0,
            src_addr: src_ip,
            dest_addr: dest_ip,
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
        let payload_len = P::serialize_payload(&self.payload)
            .or_else(|_| Err(DatagramError::PayloadWrong))?
            .len();
        self.total_len = post_padding_hlen + payload_len;
        Ok(self)
    }

    pub fn checksum(mut self) -> Result<Self, DatagramError> {
        let datagram_as_bytes =
            Vec::try_from(&self).or_else(|_| Err(DatagramError::DatagramWrong))?;

        let checksum: u16 = utils::calc_checksum(&datagram_as_bytes[..self.hlen]);

        self.checksum = checksum;

        Ok(self)
    }
}

impl<P: PduPayload<CodepointType = u8>> PduPayload for Datagram<P> {
    type Payload = Datagram<P>;
    type ErrorSpace = DatagramError;
    type CodepointType = u16;

    fn serialize_payload(payload: &Self::Payload) -> Result<Vec<u8>, Self::ErrorSpace> {
        let vec = Vec::try_from(payload).or_else(|_| Err(DatagramError::AddressParsingFailed))?;
        Ok(vec)
    }

    fn deserialize_payload(
        cp: Self::CodepointType,
        payload: &[u8],
    ) -> Result<Self::Payload, Self::ErrorSpace> {
        if cp != Self::CODEPOINT {
            return Err(DatagramError::ProtocolMismatch);
        }
        let datag =
            Datagram::try_from(payload).or_else(|_| Err(DatagramError::AddressParsingFailed))?;

        Ok(datag)
    }

    fn codepoint(_payload: &Self::Payload) -> Self::CodepointType {
        Self::CODEPOINT
    }
    fn name() -> String {
        String::from("IPv4")
    }
}

// No need to consume the Datagram instance for serialization, so we impl for borrow
impl<P: PduPayload<CodepointType = u8>> TryFrom<&Datagram<P>> for Vec<u8> {
    type Error = DatagramError;

    fn try_from(datagram: &Datagram<P>) -> Result<Vec<u8>, Self::Error> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.push(datagram.version << 4 | (datagram.hlen / 4) as u8);
        bytes.push(datagram.dscp.bits() << 2 | datagram.ecn);
        bytes.extend_from_slice(&(datagram.total_len as u16).to_be_bytes());
        bytes.extend_from_slice(&datagram.id.to_be_bytes());
        bytes.extend_from_slice(
            &((datagram.flags.bits() as u16) << 13 | datagram.fragment_offset).to_be_bytes(),
        );
        bytes.push(datagram.ttl);
        bytes.push(P::codepoint(&datagram.payload));
        bytes.extend_from_slice(&datagram.checksum.to_be_bytes());
        bytes.extend_from_slice(&datagram.src_addr.addr_bytes());
        bytes.extend_from_slice(&datagram.dest_addr.addr_bytes());
        bytes.extend_from_slice(&datagram.opts);
        let serialized_payload = P::serialize_payload(&datagram.payload)
            .or_else(|_| Err(DatagramError::PayloadWrong))?;
        bytes.extend_from_slice(&serialized_payload);

        Ok(bytes)
    }
}

impl<P: PduPayload<CodepointType = u8>> TryFrom<&[u8]> for Datagram<P> {
    type Error = DatagramError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let hlen_in_32bit_words: usize = (buffer[0] & 0x0F) as usize;
        let hlen_in_bytes: usize = hlen_in_32bit_words * 4;
        let total_len: usize = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;

        let src_addr = IPv4Address::try_from(&buffer[12..16])?;
        let dest_addr = IPv4Address::try_from(&buffer[16..20])?;

        Ok(Self {
            version: buffer[0] >> 4,
            hlen: hlen_in_bytes,
            dscp: Dscp(buffer[1] >> 2),
            ecn: buffer[1] & 0x03,
            total_len: total_len,
            id: u16::from_be_bytes([buffer[4], buffer[5]]),
            flags: FragmentationFlags::from(buffer[6] >> 5), // 3 most significant bits
            fragment_offset: u16::from_be_bytes([buffer[6] & 0x1F, buffer[7]]),
            ttl: buffer[8],
            checksum: u16::from_be_bytes([buffer[10], buffer[11]]),
            src_addr: src_addr,
            dest_addr: dest_addr,
            // TODO: Option parser
            opts: buffer[20..hlen_in_bytes].to_vec(),
            // buffer[9] is the next protocol field aka the protocol codepoint
            payload: P::deserialize_payload(buffer[9], &buffer[hlen_in_bytes..])
                .or_else(|_| Err(DatagramError::PayloadWrong))?,
        })
    }
}

impl<P: PduPayload<CodepointType = u8>> fmt::Display for Datagram<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\nIP Protocol version: {}", self.version)?;
        write!(
            f,
            "\nDatagram Header Length: {} ({} bytes)",
            self.hlen / 4,
            self.hlen
        )?;
        write!(f, "\nType Of Service (DSCP): {}", self.dscp)?;
        write!(f, "\nTotal Datagram Length: {} bytes", self.total_len)?;
        write!(f, "\nID: {:04X}", self.id)?;
        write!(f, "\nFragmentation Flag: {}", self.flags)?;
        write!(f, "\nFragment Offset: {:02X}", self.fragment_offset)?;
        write!(f, "\nTime To Live: {}", self.ttl)?;
        write!(
            f,
            "\nNext Level Protocol: {:02X}",
            P::codepoint(&self.payload)
        )?;
        write!(f, "\nChecksum: {:04X}", self.checksum)?;
        write!(f, "\nSource Address: {}", self.src_addr)?;
        write!(f, "\nDestination Address: {}", self.dest_addr)?;
        // TODO: Option parser
        write!(f, "\nOptions: {:X?}", self.opts)?;
        // Review/Test
        write!(f, "{}", self.payload)?;

        Ok(())
    }
}
// TODO: Fragmentation
