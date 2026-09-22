use crate::net::com::{PduPayload, address::MacAddress, arp, ipv4};
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtherPayload {
    IPv4(ipv4::IPv4Payload),
    // IPv6,
    Arp(Frame<arp::Datagram>),
    Unknown(Frame<UnknownPayload>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    FrameBad,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPayload(u16, Vec<u8>);

impl PduPayload for UnknownPayload {
    type Payload = UnknownPayload;
    type ErrorSpace = FrameError;
    type CodepointType = u16;

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
pub struct Frame<P>
where
    P: PduPayload,
{
    dest_mac_address: MacAddress,
    src_mac_address: MacAddress,
    pub payload: P::Payload,
}

impl<P: PduPayload<CodepointType = u16>> Frame<P> {
    pub fn new(
        dest_mac_address: MacAddress,
        src_mac_address: MacAddress,
        payload: P::Payload,
    ) -> Self {
        Self {
            dest_mac_address: dest_mac_address,
            src_mac_address: src_mac_address,
            payload: payload,
        }
    }
}

impl<P: PduPayload<CodepointType = u16>> TryFrom<&Frame<P>> for Vec<u8> {
    type Error = FrameError;

    fn try_from(frame: &Frame<P>) -> Result<Self, Self::Error> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&frame.dest_mac_address.addr_bytes());
        bytes.extend_from_slice(&frame.src_mac_address.addr_bytes());
        // EtherType
        bytes.extend_from_slice(&P::codepoint(&frame.payload).to_be_bytes());
        let serialized_payload =
            P::serialize_payload(&frame.payload).or_else(|_| Err(FrameError::FrameBad))?;
        bytes.extend_from_slice(&serialized_payload);

        Ok(bytes)
    }
}

impl<P: PduPayload<CodepointType = u16>> TryFrom<&[u8]> for Frame<P> {
    type Error = FrameError;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        let eth_type = u16::from_be_bytes([buffer[12], buffer[13]]);

        let dest_mac =
            MacAddress::try_from(&buffer[0..6]).or_else(|_| Err(FrameError::FrameBad))?;
        let src_mac =
            MacAddress::try_from(&buffer[6..12]).or_else(|_| Err(FrameError::FrameBad))?;

        Ok(Self {
            dest_mac_address: dest_mac,
            src_mac_address: src_mac,
            payload: P::deserialize_payload(eth_type, &buffer[14..])
                .or_else(|_| Err(FrameError::FrameBad))?,
        })
    }
}

impl<P: PduPayload<CodepointType = u16>> fmt::Display for Frame<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\nSource MAC: {}", self.src_mac_address)?;
        write!(f, "\nDestination MAC: {}", self.dest_mac_address)?;
        write!(
            f,
            "\nFrame Type/Length: {:04X?} ({})",
            P::codepoint(&self.payload),
            P::name()
        )?;
        write!(f, "\nPayload: {}", self.payload)?;

        Ok(())
    }
}
