use crate::net::com::{
    PduPayload,
    address::{IPv4Address, SockAddr},
    utils,
};
use core::fmt;

pub const CODEPOINT: u8 = 0x11;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub src_port: u16,
    pub dest_port: u16,
    // Length of header + payload
    len: u16,
    checksum: u16,
    pub payload: Vec<u8>,
}

impl Segment {
    pub fn new(
        src_sock_addr: SockAddr,
        dest_sock_addr: SockAddr,
        payload: Vec<u8>,
    ) -> Result<Self, SegmentError> {
        Ok(Self {
            src_port: src_sock_addr.port().number(),
            dest_port: dest_sock_addr.port().number(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentError {
    InvalidTcpSegment,
    ProtocolMismatch,
}

impl PduPayload for Segment {
    type ErrorSpace = SegmentError;
    type CodepointType = u8;

    fn serialize(&self) -> Result<Vec<u8>, Self::ErrorSpace> {
        let vec = Vec::try_from(self).or_else(|_| Err(SegmentError::InvalidTcpSegment))?;
        Ok(vec)
    }

    fn deserialize(cp: Self::CodepointType, payload: &[u8]) -> Result<Self, Self::ErrorSpace> {
        if cp != CODEPOINT {
            return Err(SegmentError::ProtocolMismatch);
        }
        let seg = Self::try_from(payload).or_else(|_| Err(SegmentError::InvalidTcpSegment))?;
        Ok(seg)
    }
    fn codepoint(&self) -> Self::CodepointType {
        CODEPOINT
    }
    fn kind(&self) -> String {
        String::from("UDP")
    }
}

impl TryFrom<&Segment> for Vec<u8> {
    type Error = SegmentError;

    fn try_from(segment: &Segment) -> Result<Self, Self::Error> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&segment.src_port.to_be_bytes());
        bytes.extend_from_slice(&segment.dest_port.to_be_bytes());
        bytes.extend_from_slice(&segment.len.to_be_bytes());
        bytes.extend_from_slice(&segment.checksum.to_be_bytes());
        bytes.extend_from_slice(&segment.payload);

        Ok(bytes)
    }
}

impl TryFrom<&[u8]> for Segment {
    type Error = SegmentError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let seg_len = u16::from_be_bytes([buffer[4], buffer[5]]);

        let segment: Self = Self {
            src_port: u16::from_be_bytes([buffer[0], buffer[1]]),
            dest_port: u16::from_be_bytes([buffer[2], buffer[3]]),
            len: seg_len,
            checksum: u16::from_be_bytes([buffer[6], buffer[7]]),
            payload: buffer[8..].to_vec(),
        };

        Ok(segment)
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\nSource Port: {}", self.src_port)?;
        write!(f, "\nDestination Port: {}", self.dest_port)?;
        write!(f, "\nSegment Length: {} bytes", self.len)?;
        write!(f, "\nChecksum: {:X}", self.checksum)?;
        write!(f, "\nPayload: {:X?}", self.payload)?;

        Ok(())
    }
}
