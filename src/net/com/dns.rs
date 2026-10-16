// Local DNS cache lookup -> Unix doesn't have OS-level DNS caching. Implement only if DNS lookups
// become a problem
//
// In-memory cache
// DNS server cache check
// DNS lookup

enum MessageError {
    Placeholder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OpCode(u8);

impl OpCode {
    pub const QUERY: Self = Self(0x00);
    pub const INVERSE_QUERY: Self = Self(0x01);
    pub const STATUS: Self = Self(0x02);

    pub const fn bits(self) -> u8 {
        self.0
    }
}

impl From<u8> for OpCode {
    fn from(v: u8) -> Self {
        // Opcode 4 bits => u8 xxxx xxxx, 0x0F 0000 1111 => v & 0x0F = 0000 xxxx
        Self(v & 0x0F)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResponseCode(u8);

impl ResponseCode {
    pub const NO_ERROR: Self = Self(0x00);
    pub const FORMAT_ERROR: Self = Self(0x01);
    pub const SERVER_FAILURE: Self = Self(0x02);
    pub const NAME_ERROR: Self = Self(0x03);
    pub const NOT_IMPLEMENTED: Self = Self(0x04);
    pub const REFUSED: Self = Self(0x05);

    pub const fn bits(self) -> u8 {
        self.0
    }
}

impl From<u8> for ResponseCode {
    fn from(v: u8) -> Self {
        // Rcode 4 bits => u8 xxxx xxxx, 0x0F 0000 1111 => v & 0x0F = 0000 xxxx
        Self(v & 0x0F)
    }
}

pub struct Label {
    // TODO: Len Validation
    len: u8,
    data: Vec<u8>,
}

pub struct Question {
    // [RFC-1035 Section 3.1] the total length of a domain name (i.e., label octets and label
    // length octets) is restricted to 255 octets or less
    // TODO: Validation
    qname: Vec<Label>,
    qtype: RecordType,
    qclass: QueryClass,
}

pub struct DnsPayload {
    question: Vec<Question>,
    answer: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
}

pub struct Flags {
    is_query: bool,
    opcode: OpCode,
    is_auth_answer: bool,
    is_truncated: bool,
    is_recurse_desired: bool,
    is_recurse_available: bool,
    zero: u8,
    rcode: ResponseCode,
}

impl From<u16> for Flags {
    fn from(value: u16) -> Self {
        Self {
            // QR -> msb => val & 1000 0000 0000 0000 = 0x8000
            // if val == 1000 0000 0000 0000, then val & 0x8000 = 1000 0000 0000 0000
            is_query: value & 0x8000 == 0x8000,
            // Opcode -> msb + 1 - msb + 4 => val & 0111 1000 0000 0000 = 0x7800
            // 0xxx x000 0000 0000 >> 11 => 0000 0000 0000 xxxx => as u8 => xxxx
            opcode: OpCode::from(((value & 0x7800) >> 11) as u8),
            // AA -> msb + 5 => val & 0000 0100 0000 0000 => 0x0400
            is_auth_answer: value & 0x4000 == 0x04000,
            // TC -> msb + 6 => val & 0000 0010 0000 0000 => 0x0200
            is_truncated: value & 0x0200 == 0x0200,
            // RD -> msb + 7 => val & 0000 0001 0000 0000 => 0x0100
            is_recurse_desired: value & 0x0100 == 0x0100,
            // RA -> msb + 8 => val & 0000 0000 1000 0000 => 0x0080
            is_recurse_available: value & 0x0080 == 0x0080,
            zero: 0,
            // Rcode -> msb + 9 - msb + 12 => val & 0000 0000 0000 1111 => 0x000F
            // 0000 0000 0000 xxxx => as u8 => xxxx
            rcode: ResponseCode::from((value & 0x000F) as u8),
        }
    }
}

impl From<&Flags> for u16 {
    fn from(value: &Flags) -> Self {
        let bytes = u16::from(0);

        bytes &= value.is_query << 15; // x000 0000 0000 0000
        bytes &= (value.opcode.bits() as u16) << 11; // 0xxx x000 0000 0000
        bytes &= value.is_auth_answer << 10; // 0000 0x00 0000 0000
        bytes &= value.is_truncated << 9; // 0000 00x0 0000 0000
        bytes &= value.is_recurse_desired << 8; // 0000 000x 0000 0000
        bytes &= value.is_recurse_available << 7; // 0000 0000 x000 0000
        bytes &= (value.zero as u16) << 4; // 0000 0000 0xxx 0000
        bytes &= value.rcode.bits() as u16; // 0000 0000 0000 xxxx

        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    id: u16,
    flags: Flags,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
    payload: DnsPayload,
}

impl Message {
    // In bytes
    const HEADER_LEN: usize = 12;
}

impl Segment {
    pub fn new(
        src_sock_addr: SockAddr,
        dest_sock_addr: SockAddr,
        payload: Vec<u8>,
    ) -> Result<Self, SegmentError> {
        Ok(Self {
            src_port: src_sock_addr.port(),
            dest_port: dest_sock_addr.port(),
            // UDP Header as no variable-size fields, it's always 8 bytes
            len: 8 + payload.len() as u16,
            checksum: 0,
            payload: payload,
        })
    }

    // TODO: This is exactly the same as for TCP. The apporach is protocol agnostic at least for
    // these 2. Review if modularization is useful
    pub fn checksum_ipv4(
        mut self,
        src_ip: &IPv4Address,
        dest_ip: &IPv4Address,
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
        if cp != CODEPOINT {
            return Err(SegmentError::ProtocolMismatch);
        }
        let seg = Segment::try_from(payload).or_else(|_| Err(SegmentError::InvalidTcpSegment))?;
        Ok(seg)
    }
    fn codepoint(_payload: &Self::Payload) -> Self::CodepointType {
        CODEPOINT
    }
    fn name() -> String {
        String::from("UDP")
    }
}

impl TryFrom<&Message> for Vec<u8> {
    type Error = MessageError;

    fn try_from(segment: &Message) -> Result<Self, Self::Error> {
        let mut bytes: Vec<u8> = Vec::new();

        Ok(bytes)
    }
}

impl TryFrom<&[u8]> for Message {
    type Error = MessageError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        Ok(segment)
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\nSource Port: {}", self.src_port)?;
        write!(f, "\nDestination Port: {}", self.dest_port)?;
        write!(f, "\nSegment Length: {} bytes", self.len)?;
        write!(f, "\nChecksum: {:X}", self.checksum)?;
        // write!(f, "\nPayload: {:X?}", self.payload)?;

        Ok(())
    }
}

fn parse_question_labels(buffer: &[u8]) -> Vec<Label> {
    let labels = Vec::new();

    // Question field immediately follows the header and the labels are contained in the first
    // "sub-field" which is qname, so the very first byte after the header is a label length octet
    //
    // We iterate from the byte position after the header to the end of the buffer until we find the zero
    // length octet
    for i in Message::HEADER_LEN..=buffer.len() {
        // [rfc-1035 section 3.1] The high order two bits of every length octet must be zero, and the
        // remaining six bits of the length field limit the label to 63 octets or less
        // 0011 1111 => 0x3f
        let label_len = (buffer[i] & 0x3f) as usize;

        if label_len == 0x00 {
            break;
        }

        let label_first_octet = i + 1;
        let label_last_octet = i + label_len;
        let label_bytes = buffer[label_first_octet..label_last_octet].to_vec();

        let label = Label {
            len: label_len as u8,
            data: label_bytes,
        };
        labels.push(label);
        // Jump to next len octect by advancing i by 1 (for the len octect) + the number of following octets aka label_len
        i += 1 + label_len;
    }

    labels
}
