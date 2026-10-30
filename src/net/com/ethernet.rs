use crate::net::com::{PduPayload, address::MacAddress};
use core::fmt;

// 14 byte header + 46 byte minimum payload size discounting FCS which is added by the NIC
const ETH_MIN_FRAME_LEN_NO_FCS: usize = 60;
// 14 byte header + 1500 max payload size discounting FCS which is added by the NIC
const ETH_MAX_FRAME_LEN_NO_FCS: usize = 1514;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    FrameBad,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownPayload(u16, Vec<u8>);

impl PduPayload for UnknownPayload {
    type ErrorSpace = FrameError;
    type CodepointType = u16;

    fn serialize(&self) -> Result<Vec<u8>, Self::ErrorSpace> {
        Ok(self.1.to_vec())
    }
    fn deserialize(cp: Self::CodepointType, payload: &[u8]) -> Result<Self, Self::ErrorSpace> {
        Ok(Self(cp, payload.to_vec()))
    }
    fn codepoint(&self) -> Self::CodepointType {
        self.0
    }
    fn kind(&self) -> String {
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
pub struct Frame<P: PduPayload<CodepointType = u16>> {
    dest_mac_address: MacAddress,
    src_mac_address: MacAddress,
    pub payload: P,
}

impl<P: PduPayload<CodepointType = u16>> Frame<P> {
    pub fn new(dest_mac_address: MacAddress, src_mac_address: MacAddress, payload: P) -> Self {
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
        let serialized_payload = frame
            .payload
            .serialize()
            .or_else(|_| Err(FrameError::FrameBad))?;
        bytes.extend_from_slice(&serialized_payload);

        if bytes.len() > ETH_MAX_FRAME_LEN_NO_FCS {
            return Err(FrameError::FrameBad);
        }

        if bytes.len() < ETH_MIN_FRAME_LEN_NO_FCS {
            let padding_len = ETH_MIN_FRAME_LEN_NO_FCS - bytes.len();
            for _ in 0..padding_len {
                bytes.push(0x00);
            }
        }

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
            payload: P::deserialize(eth_type, &buffer[14..])
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
            self.payload.codepoint(),
            self.payload.kind()
        )?;
        write!(f, "\nPayload: {}", self.payload)?;

        Ok(())
    }
}
