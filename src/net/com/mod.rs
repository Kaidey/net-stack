use std::fmt;

pub mod address;
pub mod arp;
pub mod dns;
pub mod ethernet;
pub mod ipv4;
pub mod tcp;
pub mod udp;
pub mod tls;
pub mod utils;

pub trait PduPayload: Sized + fmt::Display {
    type ErrorSpace;
    type CodepointType;

    fn serialize(&self) -> Result<Vec<u8>, Self::ErrorSpace>;
    fn deserialize(
        codepoint: Self::CodepointType,
        payload: &[u8],
    ) -> Result<Self, Self::ErrorSpace>;
    fn codepoint(&self) -> Self::CodepointType;
    fn kind(&self) -> String;
}
