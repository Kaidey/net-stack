// Local DNS cache lookup -> Unix doesn't have OS-level DNS caching. Implement only if DNS lookups
// become a problem
//
// In-memory cache
// DNS server cache check
// DNS lookup

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    InvalidRecordClass,
    InvalidRecordType,
    UnexpectedQuestionCount,
    PayloadParsingFailed,
    InvalidName,
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
    pub fn parse(buffer: &[u8], rr_start: usize) -> Result<Self, RecordError> {
        // first byte of the record is the first byte of the name field
        let name_field =
            Name::parse(buffer, rr_start).map_err(|_| RecordError::RecordParsingFailed)?;

        let name_end = name_field.field_len;

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

        len += self.name.field_len;
        len += self.rtype.wire_len();
        len += self.class.wire_len();
        len += 6; // ttl -> u32 -> 4 bytes + rdlen -> u16 -> 2 bytes
        len += self.rdata.len();

        len
    }
}

impl TryFrom<&Record> for Vec<u8> {
    type Error = RecordError;

    fn try_from(record: &Record) -> Result<Self, Self::Error> {
        let mut bytes: Vec<u8> = Vec::new();

        let (name_bytes, _) =
            Name::serialize(&record.name.parsed).map_err(|_| RecordError::RecordParsingFailed)?;

        bytes.extend_from_slice(&name_bytes);
        bytes.extend_from_slice(&record.rtype.bits().to_be_bytes());
        bytes.extend_from_slice(&record.class.bits().to_be_bytes());
        bytes.extend_from_slice(&record.ttl.to_be_bytes());
        bytes.extend_from_slice(&record.rdlen.to_be_bytes());
        bytes.extend_from_slice(&record.rdata);

        Ok(bytes)
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
pub enum NameError {
    UnknownControlByte,
    NameParseFailed,
    InvalidLabel,
    NameTooLong,
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameControlByte {
    // Contains the number of bytes for this label
    LabelLen(u8),
    // Contains the pointer offset, which is relative to the start of the Message (1st header byte)
    Pointer(u8),
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
                // xxxx xxxx & 0011 1111 => 00xx xxxx
                let ptr_offset = val & 0x3F;

                Ok(Self::Pointer(ptr_offset))
            }
            _ => Err(NameError::UnknownControlByte),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// This struct representes the whole name field, including control bytes (pointer/label len/0-length
// byte)
pub struct Name {
    parsed: String,
    field_len: usize,
}

impl Name {
    pub fn parse(buffer: &[u8], name_start: usize) -> Result<Self, NameError> {
        let mut name_end = false;

        let mut buf_cursor_pos = name_start;
        let mut jumped = false;

        let mut parsed_name = String::new();
        let mut field_len: usize = 0;

        while !name_end {
            let byte = *buffer.get(buf_cursor_pos).ok_or(NameError::Truncated)?;

            match NameControlByte::try_from(byte).map_err(|_| NameError::NameParseFailed)? {
                NameControlByte::LabelLen(len) => {
                    let label_start = buf_cursor_pos + 1;
                    let label_end = label_start + len as usize;

                    let label_bytes = buffer
                        .get(label_start..label_end)
                        // Buffer is truncated and ends before all label bytes are read
                        .ok_or(NameError::Truncated)?;

                    let label =
                        std::str::from_utf8(label_bytes).map_err(|_| NameError::NameParseFailed)?;

                    parsed_name.push_str(label);
                    parsed_name.push('.');

                    if parsed_name.len() > 254 {
                        return Err(NameError::NameTooLong);
                    }

                    // The root name field ends whenever a pointer is reached, which replaces the
                    // 0-length byte
                    if !jumped {
                        field_len += len as usize + 1; // label + its control byte
                    }

                    buf_cursor_pos = label_end;
                }
                NameControlByte::Pointer(offset_high_bits) => {
                    // Points to the start of a ctrl byte
                    // offset_6_bits    => 00xx xxxx 0000 0000
                    // buffer[1] as u16 => 0000 0000 xxxx xxxx
                    let low_bits = *buffer.get(buf_cursor_pos + 1).ok_or(NameError::Truncated)?;

                    if !jumped {
                        field_len += 2; // the field ends after these 2 bytes
                        jumped = true;
                    }

                    // (xxxx xxxx as u16) << 8 | 0000 0000 yyyy yyyy =>
                    // 0000 0000 xxxx xxxx << 8 | 0000 0000 yyyy yyyy =>
                    // xxxx xxxx 0000 0000 | 0000 0000 yyyy yyyy => xxxx xxxx yyyy yyyy
                    buf_cursor_pos = ((offset_high_bits as u16) << 8 | low_bits as u16) as usize;
                }
                NameControlByte::End => {
                    if !jumped {
                        field_len += 1;
                    }
                    name_end = true;
                }
            }
        }

        if parsed_name.len() > 255 {
            return Err(NameError::NameTooLong);
        }

        let name_field = Name {
            parsed: parsed_name,
            field_len: field_len as usize,
        };

        Ok(name_field)
    }

    pub fn serialize(name: &str) -> Result<(Vec<u8>, usize), NameError> {
        if name.len() > 255 {
            return Err(NameError::NameTooLong);
        }

        let name = name.strip_suffix('.').unwrap_or(name);

        let mut bytes = Vec::new();

        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(NameError::InvalidLabel);
            }
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0); // 0-length byte that ends the name field

        let field_len = bytes.len();

        Ok((bytes, field_len))
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
        self.qname.field_len + self.qtype.wire_len() + self.qclass.wire_len()
    }
}

impl TryFrom<&[u8]> for Question {
    type Error = MessageError;
    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let qname =
            Name::parse(&buffer, Message::HEADER_LEN).map_err(|_| MessageError::Placeholder)?;

        let name_end = Message::HEADER_LEN + qname.field_len;

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

impl TryFrom<&Question> for Vec<u8> {
    type Error = MessageError;
    fn try_from(q: &Question) -> Result<Self, Self::Error> {
        let mut bytes = Vec::new();

        let (name_field_bytes, _) =
            Name::serialize(&q.qname.parsed).map_err(|_| MessageError::PayloadParsingFailed)?;

        bytes.extend_from_slice(&name_field_bytes);
        bytes.extend_from_slice(&q.qtype.bits().to_be_bytes());
        bytes.extend_from_slice(&q.qclass.bits().to_be_bytes());

        Ok(bytes)
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\nQName: {}",
            self.qname
                .parsed
                .strip_suffix(".")
                .unwrap_or(&self.qname.parsed)
        )?;
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

impl TryFrom<&DnsPayload> for Vec<u8> {
    type Error = MessageError;

    fn try_from(p: &DnsPayload) -> Result<Self, Self::Error> {
        let mut bytes = Vec::new();

        let question: Vec<u8> =
            Vec::<u8>::try_from(&p.question).map_err(|_| MessageError::PayloadParsingFailed)?;
        let mut ans_wire: Vec<u8> = Vec::new();
        let mut auth_wire: Vec<u8> = Vec::new();
        let mut add_wire: Vec<u8> = Vec::new();

        for an_r in &p.answer {
            let rec_bytes =
                Vec::<u8>::try_from(an_r).map_err(|_| MessageError::PayloadParsingFailed)?;
            ans_wire.extend_from_slice(&rec_bytes);
        }
        for ns_r in &p.authority {
            let rec_bytes =
                Vec::<u8>::try_from(ns_r).map_err(|_| MessageError::PayloadParsingFailed)?;
            auth_wire.extend_from_slice(&rec_bytes);
        }
        for ar_r in &p.additional {
            let rec_bytes =
                Vec::<u8>::try_from(ar_r).map_err(|_| MessageError::PayloadParsingFailed)?;
            add_wire.extend_from_slice(&rec_bytes);
        }

        bytes.extend_from_slice(&question);
        bytes.extend_from_slice(&ans_wire);
        bytes.extend_from_slice(&auth_wire);
        bytes.extend_from_slice(&add_wire);

        Ok(bytes)
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
    is_response: bool,
    opcode: OpCode,
    is_auth_answer: bool,
    is_truncated: bool,
    is_recurse_desired: bool,
    is_recurse_available: bool,
    rcode: ResponseCode,
}

impl From<u16> for Flags {
    fn from(buffer: u16) -> Self {
        Self {
            // QR -> msb => val & 1000 0000 0000 0000 = 0x8000
            // if val == 1000 0000 0000 0000, then val & 0x8000 = 1000 0000 0000 0000
            is_response: buffer & 0x8000 == 0x8000,
            // Opcode -> msb + 1 - msb + 4 => val & 0111 1000 0000 0000 = 0x7800
            // 0xxx x000 0000 0000 >> 11 => 0000 0000 0000 xxxx => as u8 => 0000 xxxx
            opcode: OpCode::extract_bits(((buffer & 0x7800) >> 11) as u8),
            // AA -> msb + 5 => val & 0000 0100 0000 0000 => 0x0400
            is_auth_answer: buffer & 0x4000 == 0x4000,
            // TC -> msb + 6 => val & 0000 0010 0000 0000 => 0x0200
            is_truncated: buffer & 0x0200 == 0x0200,
            // RD -> msb + 7 => val & 0000 0001 0000 0000 => 0x0100
            is_recurse_desired: buffer & 0x0100 == 0x0100,
            // RA -> msb + 8 => val & 0000 0000 1000 0000 => 0x0080
            is_recurse_available: buffer & 0x0080 == 0x0080,
            // Rcode -> msb + 9 - msb + 12 => val & 0000 0000 0000 1111 => 0x000F
            // 0000 0000 0000 xxxx => as u8 => xxxx
            rcode: ResponseCode::extract_bits((buffer & 0x000F) as u8),
        }
    }
}

impl From<&Flags> for u16 {
    fn from(value: &Flags) -> Self {
        let mut bytes = 0u16;

        bytes |= (value.is_response as u16) << 15; //  x000 0000 0000 0000
        bytes |= (value.opcode.bits() as u16) << 11; // 0xxx x000 0000 0000
        bytes |= (value.is_auth_answer as u16) << 10; // 0000 0x00 0000 0000
        bytes |= (value.is_truncated as u16) << 9; // 0000 00x0 0000 0000
        bytes |= (value.is_recurse_desired as u16) << 8; // 0000 000x 0000 0000
        bytes |= (value.is_recurse_available as u16) << 7; // 0000 0000 x000 0000
        bytes |= value.rcode.bits() as u16; // 0000 0000 0000 xxxx

        bytes
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\nIs Response: {}", self.is_response)?;
        write!(f, "\nOpCode: {}", self.opcode)?;
        write!(f, "\nIs Authoritative Answer: {}", self.is_auth_answer)?;
        write!(f, "\nIs Truncated: {}", self.is_truncated)?;
        write!(f, "\nIs Recurse Desired: {}", self.is_recurse_desired)?;
        write!(f, "\nIs Recurse Available: {}", self.is_recurse_available)?;
        write!(f, "\nResponse Code: {}", self.rcode)?;

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

    pub fn new(name: &str) -> Result<Self, MessageError> {
        // TODO: The usage of serialize() makes no sense. Rethink the Name type
        let (_, field_len) = Name::serialize(name).map_err(|_| MessageError::InvalidName)?;
        let name_field = Name {
            parsed: String::from(name),
            field_len: field_len,
        };

        let flags = Flags {
            is_response: false,
            opcode: OpCode::QUERY,
            is_auth_answer: false,
            is_truncated: false,
            is_recurse_desired: true,
            is_recurse_available: false,
            rcode: ResponseCode::NO_ERROR,
        };

        let question = Question {
            qname: name_field,
            qtype: Type::A,
            qclass: Class::IN,
        };

        let payload = DnsPayload {
            question: question,
            answer: vec![],
            authority: vec![],
            additional: vec![],
        };

        let mut buf: [u8; 2] = [0, 0];

        let res: isize = unsafe { libc::getrandom(buf.as_mut_ptr() as _, buf.len(), 0) };

        if res != buf.len() as isize {
            return Err(MessageError::Placeholder);
        }

        Ok(Self {
            id: u16::from_ne_bytes(buf),
            flags: flags,
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
            payload: payload,
        })
    }
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
            &buffer,
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
        let mut bytes: Vec<u8> = Vec::new();

        let serialized_payload =
            Vec::<u8>::try_from(&msg.payload).map_err(|_| MessageError::PayloadParsingFailed)?;

        bytes.extend_from_slice(&msg.id.to_be_bytes());
        bytes.extend_from_slice(&u16::from(&msg.flags).to_be_bytes());
        bytes.extend_from_slice(&msg.qd_count.to_be_bytes());
        bytes.extend_from_slice(&msg.an_count.to_be_bytes());
        bytes.extend_from_slice(&msg.ns_count.to_be_bytes());
        bytes.extend_from_slice(&msg.ar_count.to_be_bytes());
        bytes.extend_from_slice(&serialized_payload);

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
