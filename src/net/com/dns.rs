// Local DNS cache lookup -> Unix doesn't have OS-level DNS caching. Implement only if DNS lookups
// become a problem
//
// In-memory cache
// DNS server cache check
// DNS lookup

use std::fmt;

pub enum MessageError {
    InvalidRecordClass,
    InvalidRecordType,
    UnexpectedQuestionCount,
    PayloadParsingFailed,
    Placeholder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OpCode(u8);

impl OpCode {
    pub const QUERY: Self = Self(0x00);
    pub const INVERSE_QUERY: Self = Self(0x01);
    pub const STATUS: Self = Self(0x02);

    pub fn bits(self) -> u8 {
        self.0
    }

    // OpCode field is bits 2-5 (in network byte order) of the first byte of the flags field
    // Mask = 0111 1000 -> 0x78
    pub fn extract_bits(byte: u8) -> Self {
        // (xxxx xxxx) & 0111 1000 >> 3 => 0xxx x000 >> 3 => 0000 xxxx
        Self((byte & 0x78) >> 3)
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();

        match *self {
            Self::QUERY => write!(f, "{} ({})", bits, "Query")?,
            Self::INVERSE_QUERY => write!(f, "{} ({})", bits, "Inverse Query")?,
            Self::STATUS => write!(f, "{} ({})", bits, "Status")?,
            _ => write!(f, "{} ({})", bits, "Unknown")?,
        }
        Ok(())
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

    pub fn bits(self) -> u8 {
        self.0
    }

    // RCode field is the last 4 bits of the second byte of the flags field
    pub fn extract_bits(byte: u8) -> Self {
        Self(byte & 0x0F)
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.bits();

        match *self {
            Self::NO_ERROR => write!(f, "{} ({})", bits, "No Errors")?,
            Self::FORMAT_ERROR => write!(f, "{} ({})", bits, "Message Format Incorrect")?,
            Self::SERVER_FAILURE => write!(f, "{} ({})", bits, "Server Failure")?,
            Self::NAME_ERROR => write!(f, "{} ({})", bits, "Domain Name Not Found")?,
            Self::NOT_IMPLEMENTED => write!(f, "{} ({})", bits, "Query Not Implemented")?,
            Self::REFUSED => write!(f, "Response Code: {} ({})", bits, "Query Refused")?,
            _ => write!(f, "{} ({})", bits, "Unknown")?,
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Type(u16);

impl Type {
    pub const A: Self = Self(0x0001);
    pub const NS: Self = Self(0x0002);
    pub const CNAME: Self = Self(0x0005);
    pub const SOA: Self = Self(0x0006);
    pub const WKS: Self = Self(0x000B);
    pub const PTR: Self = Self(0x000C);
    pub const HINFO: Self = Self(0x000D);
    pub const MINFO: Self = Self(0x000E);
    pub const MX: Self = Self(0x000F);
    pub const TXT: Self = Self(0x0010);
    pub const AAAA: Self = Self(0x001F);

    // QType only
    pub const AXFR: Self = Self(0x00FC);
    pub const MAILB: Self = Self(0x00FD);
    pub const MAILA: Self = Self(0x00FE);
    pub const ALL: Self = Self(0x00FF);

    pub fn bits(&self) -> u16 {
        self.0
    }

    pub fn is_record_type(&self) -> bool {
        match *self {
            // [RFC-1035 Section 3.2.3] All Types can be QType values but not all can be Record Type values
            // TODO: Review approach
            Self::A => true,
            Self::NS => true,
            Self::CNAME => true,
            Self::SOA => true,
            Self::WKS => true,
            Self::PTR => true,
            Self::HINFO => true,
            Self::MINFO => true,
            Self::MX => true,
            Self::TXT => true,
            Self::AAAA => true,
            _ => false,
        }
    }

    fn wire_len(&self) -> usize {
        2
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::A => write!(f, "{} ({})", self.bits(), "Host Address")?,
            Self::NS => write!(f, "{} ({})", self.bits(), "Authoritative Server")?,
            Self::CNAME => write!(f, "{} ({})", self.bits(), "Canoninal Name")?,
            Self::SOA => write!(f, "{} ({})", self.bits(), "Authority Zone Start")?,
            Self::WKS => write!(f, "{} ({})", self.bits(), "Well Known Service")?,
            Self::PTR => write!(f, "{} ({})", self.bits(), "Domain Name Pointer")?,
            Self::HINFO => write!(f, "{} ({})", self.bits(), "Host Info")?,
            Self::MINFO => write!(f, "{} ({})", self.bits(), "Mail Info")?,
            Self::MX => write!(f, "{} ({})", self.bits(), "Mail Exchange")?,
            Self::TXT => write!(f, "{} ({})", self.bits(), "Text Info")?,
            Self::AAAA => write!(f, "{} ({})", self.bits(), "IPv6 Host Address")?,
            Self::AXFR => write!(f, "{} ({})", self.bits(), "Zone Transfer")?,
            Self::MAILB => write!(f, "{} ({})", self.bits(), "Mailbox Records")?,
            Self::ALL => write!(f, "{} ({})", self.bits(), "All Records")?,
            _ => write!(f, "{} ({})", self.bits(), "Unknown")?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Class(u16);

impl Class {
    pub const IN: Self = Self(0x0001);
    pub const CH: Self = Self(0x0003);
    pub const HS: Self = Self(0x0004);
    pub const ANY: Self = Self(0x00FF);

    pub fn bits(&self) -> u16 {
        self.0
    }

    pub fn is_record_class(&self) -> bool {
        match *self {
            // [RFC-1035 Section 3.2.4] All Classes can be QClass values but not all can be Record Class values
            Self::IN => true,
            Self::CH => true,
            Self::HS => true,
            _ => false,
        }
    }

    fn wire_len(&self) -> usize {
        2
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::IN => write!(f, "{} ({})", self.bits(), "Internet")?,
            Self::CH => write!(f, "{} ({})", self.bits(), "CHAOS")?,
            Self::HS => write!(f, "{} ({})", self.bits(), "Hesiod")?,
            Self::ANY => write!(f, "{} ({})", self.bits(), "Any")?,
            _ => write!(f, "{} ({})", self.bits(), "Unknown")?,
        }
        Ok(())
    }
}

pub enum RecordError {
    RecordParsingFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    name: Name,
    rtype: Type,
    class: Class,
    ttl: u32,
    rdlen: u16,
    rdata: Vec<u8>,
}

impl Record {
    // Assumes buffer is the headerless message
    pub fn parse(buffer: &[u8], rr_start: usize) -> Result<Self, RecordError> {
        // first byte of the record is the first byte of the name field
        let name_field =
            Name::parse(buffer, rr_start).map_err(|_| RecordError::RecordParsingFailed)?;

        let name_end = name_field.wire_len();

        let rtype_bytes = u16::from_be_bytes([buffer[name_end], buffer[name_end + 1]]);
        let rtype = Type(rtype_bytes);

        let class_bytes = u16::from_be_bytes([buffer[name_end + 2], buffer[name_end + 3]]);
        let class = Class(class_bytes);

        let ttl = u32::from_be_bytes([
            buffer[name_end + 4],
            buffer[name_end + 5],
            buffer[name_end + 6],
            buffer[name_end + 7],
        ]);

        let rdlen = u16::from_be_bytes([buffer[name_end + 8], buffer[name_end + 9]]);

        let rdata = buffer[name_end + 10..].to_vec();

        Ok(Self {
            name: name_field,
            rtype: rtype,
            class: class,
            ttl: ttl,
            rdlen: rdlen,
            rdata: rdata,
        })
    }

    pub fn wire_len(&self) -> usize {
        let mut len = 0;

        len += self.name.wire_len();
        len += self.rtype.wire_len();
        len += self.class.wire_len();
        len += 6; // ttl -> u32 -> 4 bytes + rdlen -> u16 -> 2 bytes
        len += self.rdata.len();

        len
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\nName: {}", self.name)?;
        write!(f, "\nRecord Type: {}", self.rtype)?;
        write!(f, "\nRecord Class: {}", self.class)?;
        write!(f, "\nTtl: {}", self.ttl)?;
        write!(f, "\nData Length: {}", self.rdlen)?;
        // TODO: How to represent record data?
        // write!(f, "\nData: {}", self.rdata)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameError {
    UnknownControlByte,
    NameParseFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameControlByte {
    // Contains the number of bytes for this label
    LabelLen(u8),
    // Contains the pointer offset, which is relative to the start of the Message (1st header byte)
    Pointer(u16),
    End,
}

impl TryFrom<u8> for NameControlByte {
    type Error = NameError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            // If the value is 0, it's the end of the name field
            0x0000 => Ok(Self::End),
            // First 2 bits of the first byte determine if it's a label or a pointer
            // xxxx xxxx & 1100 0000 == 0000 0000
            val if val & 0xC0 == 0x00 => {
                // For a label control byte, the second byte is ignored as label len is only 6 bits
                // xxxx xxxx & 0011 1111 => 00xx xxxx
                let len_bits = val & 0x3F;

                Ok(NameControlByte::LabelLen(len_bits))
            }
            // xxxx xxxx & 1100 0000 == 1100 0000
            val if val & 0xC0 == 0xC0 => {
                // For a pointer control byte, the offset will be the lower 6 bits of the first byte
                // and the entirety of the second byte for a 14 bit offset
                //
                // Here we only prepare the offset u16 with the first 6 bits (the lowest of the
                // control byte)
                //
                // ((xxxx xxxx & 0011 1111) as u16) << 8 => (00xx xxxx as u16) << 8 => 0000 0000 00xx xxxx << 8 => 00xx xxxx 0000 0000
                let ptr_offset = ((val & 0x3F) as u16) << 8;

                Ok(Self::Pointer(ptr_offset))
            }
            _ => Err(NameError::UnknownControlByte),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// This struct representes the whole name field, including control bytes (pointer/label len)
pub struct Name {
    parsed: String,
    // This is not a list of all label bytes that make up the parsed name, but how many label bytes are in
    // the name field. Some of them could be in different places in the buffer, point to by
    // pointer control bytes in the field
    label_bytes: Vec<u8>,
    ctrl_bytes: Vec<NameControlByte>,
}

impl Name {
    // Assumes buffer is the headerless messsage
    pub fn parse(buffer: &[u8], name_start: usize) -> Result<Self, NameError> {
        let mut name_end = false;
        let mut is_label_in_field = true;

        let mut label_bytes_in_field = Vec::new();
        let mut all_label_bytes = Vec::new();
        let mut ctrl_bytes = Vec::new();

        let mut next_ctrl_byte_idx = name_start;

        while !name_end {
            let ctrl_byte = NameControlByte::try_from(buffer[next_ctrl_byte_idx])
                .map_err(|_| NameError::NameParseFailed)?;

            ctrl_bytes.push(ctrl_byte.clone());

            match ctrl_byte {
                NameControlByte::LabelLen(len) => {
                    let label_end = len as usize + 1;

                    if is_label_in_field {
                        label_bytes_in_field.extend_from_slice(&buffer[1..label_end]);
                    }
                    all_label_bytes.extend_from_slice(&buffer[1..label_end]);

                    next_ctrl_byte_idx = label_end + 1;
                }
                NameControlByte::Pointer(offset_6_bits) => {
                    // Points at a Label length byte
                    // offset_6_bits    => 00xx xxxx 0000 0000
                    // buffer[1] as u16 => 0000 0000 xxxx xxxx
                    let offset = offset_6_bits | buffer[1] as u16;

                    // Offset is calculated from the first byte of the Message header
                    next_ctrl_byte_idx = offset as usize - Message::HEADER_LEN;

                    if is_label_in_field {
                        is_label_in_field = false;
                    }
                }
                NameControlByte::End => name_end = true,
            }
        }

        let full_parsed_name =
            String::from_utf8(all_label_bytes).map_err(|_| NameError::NameParseFailed)?;

        Ok(Name {
            parsed: full_parsed_name,
            label_bytes: label_bytes_in_field,
            ctrl_bytes: ctrl_bytes,
        })
    }

    // This returns the length of a name field, not the length of the name that it represents, since
    // some labels could be referenced by a pointer in the field itself
    pub fn wire_len(&self) -> usize {
        // NameControlByte::End which represents the 0-length byte that ends the name field is
        // included in ctrl_bytes
        self.label_bytes.len() + self.ctrl_bytes.len()
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.parsed)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    // [RFC-1035 Section 3.1] the total length of a domain name (i.e., label octets and label
    // length octets) is restricted to 255 octets or less
    // TODO: Validation
    qname: Name,
    qtype: Type,
    qclass: Class,
}

impl Question {
    fn wire_len(&self) -> usize {
        self.qname.wire_len() + self.qtype.wire_len() + self.qclass.wire_len()
    }
}

impl TryFrom<&[u8]> for Question {
    type Error = MessageError;
    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        // buffer is the headerless message, so the first byte is the first question byte
        let qname = Name::parse(&buffer, 0).map_err(|_| MessageError::Placeholder)?;

        let name_end = qname.wire_len();

        let qtype_bytes = u16::from_be_bytes([buffer[name_end], buffer[name_end + 1]]);
        let qtype = Type(qtype_bytes);

        let qclass_bytes = u16::from_be_bytes([buffer[name_end + 2], buffer[name_end + 3]]);
        let qclass = Class(qclass_bytes);

        Ok(Self {
            qname: qname,
            qtype: qtype,
            qclass: qclass,
        })
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\nQName: {}", self.qname.parsed)?;
        write!(f, "\nQType: {}", self.qtype)?;
        write!(f, "\nQClass: {}", self.qclass)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPayload {
    // [RFC-9619 Section 4] Question section of a DNS message with OPCODE = 0 MUST NOT contain more than one question
    question: Question,
    // Following three fields can be empty lists
    answer: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
}

impl DnsPayload {
    pub fn parse(
        buffer: &[u8],
        ancount: usize,
        nscount: usize,
        arcount: usize,
    ) -> Result<Self, MessageError> {
        let question = Question::try_from(buffer)?;

        let mut an_records: Vec<Record> = Vec::new();
        let mut ns_records: Vec<Record> = Vec::new();
        let mut ar_records: Vec<Record> = Vec::new();

        let mut next_record = question.wire_len();
        // Parse ancount records as Answer records. The next record starts in the first byte after
        // the previous aka record.wire_len()
        while an_records.len() < ancount {
            let record = Record::parse(buffer, next_record)
                .map_err(|_| MessageError::PayloadParsingFailed)?;
            an_records.push(record.clone());
            next_record = record.wire_len();
        }

        while ns_records.len() < nscount {
            let record = Record::parse(buffer, next_record)
                .map_err(|_| MessageError::PayloadParsingFailed)?;
            ns_records.push(record.clone());
            next_record = record.wire_len();
        }

        while ar_records.len() < arcount {
            let record = Record::parse(buffer, next_record)
                .map_err(|_| MessageError::PayloadParsingFailed)?;
            ar_records.push(record.clone());
            next_record = record.wire_len();
        }

        Ok(Self {
            question: question,
            answer: an_records,
            authority: ns_records,
            additional: ar_records,
        })
    }
}

impl fmt::Display for DnsPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\nQuestion: {}", self.question)?;
        write!(f, "\nAnswer: {:?}", self.answer)?;
        write!(f, "\nAuthority: {:?}", self.authority)?;
        write!(f, "\nAdditional: {:?}", self.additional)?;
        Ok(())
    }
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
    fn from(buffer: u16) -> Self {
        Self {
            // QR -> msb => val & 1000 0000 0000 0000 = 0x8000
            // if val == 1000 0000 0000 0000, then val & 0x8000 = 1000 0000 0000 0000
            is_query: buffer & 0x8000 == 0x8000,
            // Opcode -> msb + 1 - msb + 4 => val & 0111 1000 0000 0000 = 0x7800
            // 0xxx x000 0000 0000 >> 11 => 0000 0000 0000 xxxx => as u8 => 0000 xxxx
            opcode: OpCode::extract_bits(((buffer & 0x7800) >> 11) as u8),
            // AA -> msb + 5 => val & 0000 0100 0000 0000 => 0x0400
            is_auth_answer: buffer & 0x4000 == 0x04000,
            // TC -> msb + 6 => val & 0000 0010 0000 0000 => 0x0200
            is_truncated: buffer & 0x0200 == 0x0200,
            // RD -> msb + 7 => val & 0000 0001 0000 0000 => 0x0100
            is_recurse_desired: buffer & 0x0100 == 0x0100,
            // RA -> msb + 8 => val & 0000 0000 1000 0000 => 0x0080
            is_recurse_available: buffer & 0x0080 == 0x0080,
            zero: 0,
            // Rcode -> msb + 9 - msb + 12 => val & 0000 0000 0000 1111 => 0x000F
            // 0000 0000 0000 xxxx => as u8 => xxxx
            rcode: ResponseCode::extract_bits((buffer & 0x000F) as u8),
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

impl TryFrom<&[u8]> for Message {
    type Error = MessageError;
    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        // Parse header
        let id = u16::from_be_bytes([buffer[0], buffer[1]]);
        let flag_bytes = u16::from_be_bytes([buffer[2], buffer[3]]);
        let flags = Flags::from(flag_bytes);

        let qdcount = u16::from_be_bytes([buffer[4], buffer[5]]);
        let ancount = u16::from_be_bytes([buffer[6], buffer[7]]);
        let nscount = u16::from_be_bytes([buffer[8], buffer[9]]);
        let arcount = u16::from_be_bytes([buffer[10], buffer[11]]);

        // While RFC-1035 enables the possibility of a Query containing multiple questions, RFC_9619
        // squashes the ambiguity and states that it must not contain more than 1
        if qdcount != 1 {
            return Err(MessageError::UnexpectedQuestionCount);
        }

        // Parse payload
        // Payload parsing requires the entire headerless message due to name label pointers
        let payload = DnsPayload::parse(
            &buffer[Message::HEADER_LEN..],
            ancount as usize,
            nscount as usize,
            arcount as usize,
        )?;

        Ok(Self {
            id: id,
            flags: flags,
            qd_count: qdcount,
            an_count: ancount,
            ns_count: nscount,
            ar_count: arcount,
            payload: payload,
        })
    }
}

impl TryFrom<&Message> for Vec<u8> {
    type Error = MessageError;

    fn try_from(msg: &Message) -> Result<Self, Self::Error> {

        let message = MessageError::try_from(msg)

        Ok(bytes)
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
