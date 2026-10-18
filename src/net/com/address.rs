use crate::net::socket;
use crate::os;
use std::fmt;

pub enum PortGuardError {
    Placeholder,
}

// Holds the fd of a reservation socket and the reserved port number
// The socket needs to remain in scope for the port it was assigned to stay reserved for our process.
// Reservation sockets allow us to either request a free port from the kernel or guarantee that a
// client provided port is free
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortGuard {
    sock_fd: Option<i32>,
    port: u16,
    is_tcp: bool,
}

// TODO: Review usage of PortGuard for ports with reservation socket and ports without
impl PortGuard {
    pub fn new(
        request_port: u16,
        is_tcp_port: bool,
        use_reservation_socket: bool,
    ) -> Result<Self, PortGuardError> {
        if !use_reservation_socket {
            return Ok(PortGuard {
                sock_fd: None,
                port: request_port,
                is_tcp: is_tcp_port,
            });
        } else {
            let (fd, port) = socket::new_reservation_sock(request_port)
                .map_err(|_| PortGuardError::Placeholder)?;

            let mut pg = Self {
                sock_fd: Some(fd),
                port: port,
                is_tcp: is_tcp_port,
            };

            if is_tcp_port {
                match os::switch_iptables_kernel_rst_block(port, os::IpTableRuleAction::Insert) {
                    Ok(true) => {
                        pg.is_tcp = true;
                        return Ok(pg);
                    }
                    _ => {
                        unsafe {
                            libc::close(fd);
                        }
                        return Err(PortGuardError::Placeholder);
                    }
                }
            } else {
                return Ok(pg);
            }
        }
    }

    pub fn port_number(&self) -> u16 {
        self.port
    }
}

// Implements behaviour for when a value is dropped (goes out of scope)
// E.g: if an object holding a PortGuard type is dropped
impl Drop for PortGuard {
    fn drop(&mut self) {
        if self.is_tcp {
            match os::switch_iptables_kernel_rst_block(self.port, os::IpTableRuleAction::Delete) {
                Ok(true) => {
                    println!("Kernel-rst-block drop rule deleted successfully from iptables")
                }
                Ok(false) => eprintln!(
                    "warning: deleting kernel-rst-block drop rule for port {} failed",
                    self.port
                ),
                Err(e) => eprintln!(
                    "warning: deleting kernel-rst-block drop rule failed, could not run iptables: {e}"
                ),
            }
        }
        // If this PortGuard uses a reservation socket
        if let Some(sock) = self.sock_fd {
            unsafe {
                libc::close(sock);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    NotEnoughOctets,
    ConvertionFailed,
    InvalidAddress,
    MissingPort,
    InvalidPort,
    NotImplemented,
    AddressFamilyMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolAddress {
    IPv4(IPv4Address),
    IPv6(IPv6Address),
}

impl ProtocolAddress {
    pub fn from_wire(cp: u16, addr_bytes: &[u8]) -> Option<Self> {
        match cp {
            IPv4Address::CODEPOINT => Some(ProtocolAddress::IPv4(IPv4Address(
                addr_bytes.try_into().ok()?,
            ))),

            // cp if cp == IPv6Address::addr_codepoint() => Some(IPv6Address(addr_bytes)),
            _ => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            ProtocolAddress::IPv4(_) => "IPv4",
            ProtocolAddress::IPv6(_) => "IPv6",
        }
    }

    pub fn codepoint(&self) -> u16 {
        match self {
            Self::IPv4(_addr) => IPv4Address::CODEPOINT,
            Self::IPv6(_addr) => IPv6Address::CODEPOINT,
        }
    }

    pub fn length(&self) -> usize {
        match self {
            Self::IPv4(_addr) => IPv4Address::LENGTH,
            Self::IPv6(_addr) => IPv6Address::LENGTH,
        }
    }

    pub fn addr_bytes(&self) -> &[u8] {
        match self {
            ProtocolAddress::IPv4(addr) => addr.addr_bytes(),
            ProtocolAddress::IPv6(addr) => addr.addr_bytes(),
        }
    }
}

impl fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolAddress::IPv4(addr) => write!(f, "{}", addr),
            // TODO
            ProtocolAddress::IPv6(addr) => write!(f, "{}", addr),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardwareAddress {
    MAC(MacAddress),
}

impl HardwareAddress {
    pub fn from_wire(cp: u16, addr_bytes: &[u8]) -> Option<Self> {
        match cp {
            MacAddress::CODEPOINT => Some(HardwareAddress::MAC(MacAddress(
                addr_bytes.try_into().ok()?,
            ))),
            _ => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            HardwareAddress::MAC(_) => "MAC",
        }
    }

    pub fn codepoint(&self) -> u16 {
        match self {
            Self::MAC(_addr) => MacAddress::CODEPOINT,
        }
    }

    pub fn length(&self) -> usize {
        match self {
            Self::MAC(_) => MacAddress::LENGTH,
        }
    }

    pub fn addr_bytes(&self) -> &[u8] {
        match self {
            HardwareAddress::MAC(addr) => addr.addr_bytes(),
        }
    }
}

impl fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HardwareAddress::MAC(addr) => write!(f, "{}", addr),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const CODEPOINT: u16 = 0x0001;
    pub const LENGTH: usize = 6;
    pub const BROADCAST: Self = Self([0xFF; 6]);
    pub const ZERO: Self = Self([0; 6]);

    pub fn addr_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_all_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0, 0, 0]
    }
}

impl From<&[u8]> for MacAddress {
    fn from(bytes: &[u8]) -> Self {
        if bytes.len() != 6 {
            //TODO: Handle errors
            panic!("Wrong")
        }

        let mut byte_array: [u8; 6] = [0; 6];
        byte_array.copy_from_slice(&bytes);

        MacAddress(byte_array)
    }
}

impl TryFrom<&str> for MacAddress {
    type Error = AddressError;

    fn try_from(str: &str) -> Result<Self, AddressError> {
        let mut res: Result<Vec<u8>, AddressError> = Err(AddressError::ConvertionFailed);

        if str.len() == 0 || str.len() < MacAddress::LENGTH {
            return Err(AddressError::NotEnoughOctets);
        }

        let str_no_term_char = str.replace("\n", "").as_str().to_owned();

        let divider: &str = if str_no_term_char.contains("-") {
            "-"
        } else if str_no_term_char.contains(":") {
            ":"
        } else {
            ""
        };

        // XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX
        if divider.is_empty() == false {
            let str_split = str_no_term_char.split(divider).collect::<Vec<&str>>();
            res = (0..str_split.len())
                .map(|i| {
                    u8::from_str_radix(&str_split[i], 16)
                        .map_err(|_| AddressError::ConvertionFailed)
                })
                .collect();
        // XXXXXXXXXXXX
        } else {
            res = (0..str_no_term_char.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&str_no_term_char[i..i + 1], 16)
                        .map_err(|_| AddressError::ConvertionFailed)
                })
                .collect();
        }

        match res {
            Ok(bytes) => {
                if bytes.len() != 6 {
                    return Err(AddressError::NotEnoughOctets);
                } else {
                    let mut byte_array: [u8; 6] = [0; 6];
                    byte_array.copy_from_slice(&bytes);

                    return Ok(MacAddress(byte_array));
                }
            }
            Err(_) => return Err(AddressError::ConvertionFailed),
        }
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let as_str = self
            .0
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(":");

        write!(f, "{}", as_str)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct IPv4Address(pub [u8; 4]);

impl IPv4Address {
    pub const CODEPOINT: u16 = 0x0800;
    pub const LENGTH: usize = 4;
    pub fn addr_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for IPv4Address {
    type Error = AddressError;
    fn try_from(bytes: &[u8]) -> Result<IPv4Address, Self::Error> {
        if bytes.len() != 4 {
            return Err(AddressError::NotEnoughOctets);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IPv6Address(pub [u8; 16]);

impl IPv6Address {
    // TODO
    pub const CODEPOINT: u16 = 0x0000;
    pub const LENGTH: usize = 0;

    pub fn addr_bytes(&self) -> &[u8] {
        // TODO
        &[0 as u8]
    }
}

impl fmt::Display for IPv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Not Implemented")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddr {
    V4(IPv4Address),
    V6(IPv6Address),
}

impl IpAddr {
    pub fn addr_bytes(&self) -> &[u8] {
        match self {
            IpAddr::V4(addr) => addr.addr_bytes(),
            IpAddr::V6(_addr) => &[0],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockAddrV4(pub IPv4Address, pub PortGuard);

impl SockAddrV4 {
    pub fn addr(&self) -> IPv4Address {
        self.0
    }

    pub fn port(&self) -> PortGuard {
        self.1.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockAddrV6(pub IPv6Address, pub PortGuard);

impl SockAddrV6 {
    pub fn addr(&self) -> IPv6Address {
        self.0
    }

    pub fn port(&self) -> PortGuard {
        self.1.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SockAddr {
    V4(SockAddrV4),
    V6(SockAddrV6),
}

impl SockAddr {
    pub fn addr_bytes(&self) -> Vec<u8> {
        match self {
            Self::V4(sock_addr) => sock_addr.addr().addr_bytes().to_vec(),
            Self::V6(sock_addr) => sock_addr.addr().addr_bytes().to_vec(),
        }
    }

    pub fn port(&self) -> PortGuard {
        match self {
            Self::V4(addr) => addr.port(),
            Self::V6(addr) => addr.port(),
        }
    }
}

impl TryFrom<&SockAddr> for IPv4Address {
    type Error = AddressError;
    fn try_from(value: &SockAddr) -> Result<Self, Self::Error> {
        match value {
            SockAddr::V4(sock_addr) => Ok(sock_addr.addr().to_owned()),
            _ => return Err(AddressError::AddressFamilyMismatch),
        }
    }
}
impl TryFrom<&SockAddr> for IPv6Address {
    type Error = AddressError;
    fn try_from(value: &SockAddr) -> Result<Self, Self::Error> {
        match value {
            SockAddr::V6(sock_addr) => Ok(sock_addr.addr().to_owned()),
            _ => return Err(AddressError::AddressFamilyMismatch),
        }
    }
}

impl TryFrom<&SockAddr> for SockAddrV4 {
    type Error = AddressError;
    fn try_from(value: &SockAddr) -> Result<Self, Self::Error> {
        match value {
            SockAddr::V4(sock_addr) => Ok(sock_addr.to_owned()),
            _ => return Err(AddressError::AddressFamilyMismatch),
        }
    }
}
impl TryFrom<&SockAddr> for SockAddrV6 {
    type Error = AddressError;
    fn try_from(value: &SockAddr) -> Result<Self, Self::Error> {
        match value {
            SockAddr::V6(sock_addr) => Ok(sock_addr.to_owned()),
            _ => return Err(AddressError::AddressFamilyMismatch),
        }
    }
}

pub trait ToSockAddr {
    fn to_sock_addr(&self, is_tcp: bool) -> Result<SockAddr, AddressError>;
}

impl ToSockAddr for &str {
    fn to_sock_addr(&self, is_tcp: bool) -> Result<SockAddr, AddressError> {
        // Handles direct ip:port strings
        // TODO: Handle host names with DNS
        // TODO: Handle IPv6
        let slices = self.split(":").collect::<Vec<&str>>();

        if slices.len() != 2 || slices[1].is_empty() {
            return Err(AddressError::MissingPort);
        }

        let dest_ip = IPv4Address::try_from(slices[0]).map_err(|_| AddressError::InvalidAddress)?;

        // Radix is the same as the base of the number system we want to use (base 10 here)
        let radix: u32 = 10;

        let dest_port_digits: Vec<u32> = slices[1]
            .chars()
            .map(|c| c.to_digit(radix))
            .collect::<Option<Vec<u32>>>()
            .ok_or(AddressError::InvalidPort)?;

        let mut dest_port = 0;
        for d in dest_port_digits {
            dest_port = (dest_port as u16) * 10 + (d as u16);
        }

        let pg = PortGuard {
            sock_fd: None,
            port: dest_port,
            is_tcp: is_tcp,
        };

        Ok(SockAddr::V4(SockAddrV4(dest_ip, pg)))
    }
}
