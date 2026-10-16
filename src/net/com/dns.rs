// Local DNS cache lookup -> Unix doesn't have OS-level DNS caching. Implement only if DNS lookups
// become a problem
//
// In-memory cache
// DNS server cache check
// DNS lookup

use std::fmt;

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

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();

        match *self {
            Self::QUERY => write!(f, "\nOpCode: {} ({})", bits, "Query"),
            Self::INVERSE_QUERY => write!(f, "\nOpCode: {} ({})", bits, "Inverse Query"),
            Self::STATUS => write!(f, "\nOpCode: {} ({})", bits, "Status"),
            _ => write!(f, "\nOpCode: {} (Unknown)", bits),
        }
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

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();

        match *self {
            Self::NO_ERROR => write!(f, "\nResponse Code: {} ({})", bits, "No Errors"),
            Self::FORMAT_ERROR => write!(
                f,
                "\nResponse Code: {} ({})",
                bits, "Message Format Incorrect"
            ),
            Self::SERVER_FAILURE => write!(f, "\nResponse Code: {} ({})", bits, "Server Failure"),
            Self::NAME_ERROR => {
                write!(f, "\nResponse Code: {} ({})", bits, "Domain Name Not Found")
            }
            Self::NOT_IMPLEMENTED => {
                write!(f, "\nResponse Code: {} ({})", bits, "Query Not Implemented")
            }
            Self::REFUSED => write!(f, "Response Code: {} ({})", bits, "Query Refused"),
            _ => write!(f, "\nResponse Code: {} (Unknown)", bits),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordType(u16);

impl RecordType {
    pub const A: Self = Self(0x0001);
    pub const NS: Self = Self(0x0002);
    pub const CNAME: Self = Self(0x0005);
    pub const SOA: Self = Self(0x0006);
    pub const MX: Self = Self(0x000F);
    pub const TXT: Self = Self(0x0010);
    pub const AAAA: Self = Self(0x001F);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryClass(u16);

impl QueryClass {
    pub const IN: Self = Self(0x0001);
    pub const CS: Self = Self(0x0002);
    pub const CG: Self = Self(0x0003);
    pub const HC: Self = Self(0x0004);
    pub const ANY: Self = Self(0x00FF);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    name: Vec<u8>,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdlen: u16,
    rdata: Vec<u8>,
}

enum LabelError{
    FailedToStringifyData
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    len: u8,
    data: Vec<u8>,
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lbl_data_as_str = String::from_utf8(self.data.clone()).map_err(|_| LabelError::FailedToStringifyData).map_err(|_| fmt::Error)?;

        write!(f, "\nLabel: {} ({} bytes)", lbl_data_as_str, self.len)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    // [RFC-1035 Section 3.1] the total length of a domain name (i.e., label octets and label
    // length octets) is restricted to 255 octets or less
    // TODO: Validation
    qname: Vec<Label>,
    qtype: RecordType,
    qclass: QueryClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPayload {
    question: Vec<Question>,
    answer: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        let mut bytes = u16::from(0 as u16);

        bytes &= (value.is_query as u16) << 15; // x000 0000 0000 0000
        bytes &= (value.opcode.bits() as u16) << 11; // 0xxx x000 0000 0000
        bytes &= (value.is_auth_answer as u16) << 10; // 0000 0x00 0000 0000
        bytes &= (value.is_truncated as u16) << 9; // 0000 00x0 0000 0000
        bytes &= (value.is_recurse_desired as u16) << 8; // 0000 000x 0000 0000
        bytes &= (value.is_recurse_available as u16) << 7; // 0000 0000 x000 0000
        bytes &= (value.zero as u16) << 4; // 0000 0000 0xxx 0000
        bytes &= value.rcode.bits() as u16; // 0000 0000 0000 xxxx

        bytes
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\nQuery: {}", self.is_query)?;
        write!(f, "{}", self.opcode)?;
        write!(f, "\nAuthoritative Answer: {}", self.is_auth_answer)?;
        write!(f, "\nTruncated: {}", self.is_truncated)?;
        write!(f, "\nRecurse Desired: {}", self.is_recurse_desired)?;
        write!(f, "\nRecurse Available: {}", self.is_recurse_available)?;
        write!(f, "{}", self.rcode)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    // TODO: Id generation
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

impl TryFrom<&Message> for Vec<u8> {
    type Error = MessageError;

    fn try_from(msg: &Message) -> Result<Self, Self::Error> {
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

impl fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\nId: {}", self.id)?;
        write!(f, "\nFlags: {}", self.flags)?;
        write!(f, "\nQuestion Entries: {}", self.qd_count)?;
        write!(f, "\nAnswer Records: {}", self.an_count)?;
        write!(f, "\nAuthority Records: {}", self.ns_count)?;
        write!(f, "\nAdditional Records: {}", self.ar_count)?;
        write!(f, "\nPayload: {}", self.payload)?;

        Ok(())
    }
}

fn parse_question_labels(buffer: &[u8]) -> Vec<Label> {
    let mut labels = Vec::new();

    // Question field immediately follows the header and the labels are contained in the first
    // "sub-field" which is qname, so the very first byte after the header is a label length octet
    //
    // We iterate from the byte position after the header to the end of the buffer until we find the zero
    // length octet

    let mut label_start_idx = Message::HEADER_LEN;

    while label_start_idx < buffer.len() {
        // [rfc-1035 section 3.1] The high order two bits of every length octet must be zero, and the
        // remaining six bits of the length field limit the label to 63 octets or less
        // 0011 1111 => 0x3f
        let label_len = (buffer[label_start_idx] & 0x3f) as usize;

        if label_len == 0x00 {
            break;
        }

        let label_first_octet = label_start_idx + 1;
        let label_last_octet = label_start_idx + label_len;
        let label_bytes = buffer[label_first_octet..label_last_octet].to_vec();

        let label = Label {
            len: label_len as u8,
            data: label_bytes,
        };
        labels.push(label);
        // Jump to next len octect by advancing i by 1 (for the len octect) + the number of following octets aka label_len
        label_start_idx += 1 + label_len;
    }

    labels
}
