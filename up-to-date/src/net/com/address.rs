use std::fmt;

pub enum AddressError{
    NotEnoughOctets
}

#[derive(Debug,Clone,PartialEq,Eq)]
pub enum ProtocolAddress {
    IPv4(IPv4Address),
    IPv6(IPv6Address),
}

impl ProtocolAddress {
    pub fn from_wire(cp: u16, addr_bytes: &[u8]) -> Option<Self> {
        match cp {
            0x0800 => Some(ProtocolAddress::IPv4(IPv4Address(
                        // TODO: Error handling
                addr_bytes.try_into().ok()?,
            ))),
            // cp if cp == IPv6Address::addr_codepoint() => Some(IPv6Address(addr_bytes)),
            _ => None,
        }
    }

    pub fn addr(&self) -> &[u8] {
        match self {
            ProtocolAddress::IPv4(addr) => addr.addr_bytes(),
            // TODO
            ProtocolAddress::IPv6(_addr) => [0, 0, 0].as_slice(),
        }
    }

    pub fn codepoint(&self) -> u16 {
        match self {
            ProtocolAddress::IPv4(_addr) => 0x0800,
            // TODO
            ProtocolAddress::IPv6(_addr) => 0x0000,
        }
    }

    pub fn length(&self) -> u8 {
        match self {
            ProtocolAddress::IPv4(_addr) => 0x04,
            // TODO
            ProtocolAddress::IPv6(_addr) => 0x00,
        }
    }

    pub fn addr_as_string(&self) -> String {
        match self {
            ProtocolAddress::IPv4(addr) => addr.to_string(),
            // TODO
            ProtocolAddress::IPv6(addr) => String::new(),
        }
    }
}

impl fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolAddress::IPv4(_addr) => write!(f, "IPv4"),
            ProtocolAddress::IPv6(_addr) => write!(f, "IPv6"),
        }
    }
}

#[derive(Debug,Clone,PartialEq,Eq)]
pub enum HardwareAddress {
    MAC(MacAddress),
}

impl HardwareAddress {
    pub fn from_wire(cp: u16, addr_bytes: &[u8]) -> Option<Self> {
        match cp {
            0x0001 => Some(HardwareAddress::MAC(MacAddress(
                addr_bytes.try_into().ok()?,
            ))),
            _ => None,
        }
    }

    pub fn addr(&self) -> &[u8] {
        match self {
            HardwareAddress::MAC(addr) => addr.addr_bytes(),
        }
    }

    pub fn codepoint(&self) -> u16 {
        match self {
            HardwareAddress::MAC(_addr) => 0x0001,
        }
    }

    pub fn length(&self) -> u8 {
        match self {
            HardwareAddress::MAC(_addr) => 0x06,
        }
    }

    pub fn addr_as_string(&self) -> String {
        match self {
            HardwareAddress::MAC(addr) => addr.to_string(),
        }
    }
}

impl fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HardwareAddress::MAC(_addr) => write!(f, "MAC"),
        }
    }
}

#[derive(Debug,Copy,Clone,PartialEq,Eq)]
pub struct IPv4Address(pub [u8; 4]);

impl IPv4Address {
    pub fn addr_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for IPv4Address {
    type Error = AddressError;
    fn try_from(bytes: &[u8]) -> Result<IPv4Address, Self::Error> {
        if bytes.len() != 4 {
            return Err(AddressError::NotEnoughOctets)
        }

        let mut byte_array: [u8; 4] = [0; 4];
        byte_array.copy_from_slice(&bytes);

        Ok(IPv4Address(byte_array))
    }
}

impl From<&str> for IPv4Address {
    fn from(str: &str) -> Self {
        let bytes = str
            .split(".")
            .map(|oct| {
                String::from(oct)
                    .parse::<u8>()
                    .expect("Error converting IPv4 address to bytes")
            })
            .collect::<Vec<u8>>();

        if bytes.len() != 4 {
            //TODO: Handle errors
            panic!("Wrong")
        }

        let mut byte_array: [u8; 4] = [0; 4];
        byte_array.copy_from_slice(&bytes);

        IPv4Address(byte_array)
    }
}

impl fmt::Display for IPv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let as_str = self
            .0
            .iter()
            .map(|b| format!("{}", b))
            .collect::<Vec<String>>()
            .join(".");

        write!(f, "{}", as_str)
    }
}

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub fn addr_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for MacAddress {
    fn from(bytes: &[u8]) -> Self {
        if bytes.len() != 4 {
            //TODO: Handle errors
            panic!("Wrong")
        }

        let mut byte_array: [u8; 6] = [0; 6];
        byte_array.copy_from_slice(&bytes);

        MacAddress(byte_array)
    }
}

impl From<&str> for MacAddress {
    fn from(str: &str) -> Self {
        let bytes = str
            .split("-")
            .map(|oct| {
                String::from(oct)
                    .parse::<u8>()
                    .expect("Error converting MAC address to bytes")
            })
            .collect::<Vec<u8>>();

        if bytes.len() != 6 {
            //TODO: Handle errors
            panic!("Wrong")
        }

        let mut byte_array: [u8; 6] = [0; 6];
        byte_array.copy_from_slice(&bytes);

        MacAddress(byte_array)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let as_str = self
            .0
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join("-");

        write!(f, "{}", as_str)
    }
}

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct IPv6Address(String);
