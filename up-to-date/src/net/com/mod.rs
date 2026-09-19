use std::fmt;

pub mod address;
pub mod arp;
pub mod ethernet;
pub mod ipv4;
pub mod tcp;
pub mod utils;

pub trait PduPayload {
    type Payload: fmt::Display;
    type ErrorSpace;
    type CodepointType;

    fn serialize_payload(payload: &Self::Payload) -> Result<Vec<u8>, Self::ErrorSpace>;
    fn deserialize_payload(
        codepoint: Self::CodepointType,
        payload: &[u8],
    ) -> Result<Self::Payload, Self::ErrorSpace>;
    fn codepoint(payload: &Self::Payload) -> Self::CodepointType;
    fn name() -> String;
}
