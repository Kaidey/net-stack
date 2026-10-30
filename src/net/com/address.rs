use crate::net::{resolve_domain_name, socket};
use crate::os;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Port {
    Reserved(PortGuard),
    Unreserved(u16),
}

impl Port {
    pub fn number(&self) -> u16 {
        match self {
            Self::Reserved(port_guard) => port_guard.port,
            Self::Unreserved(port) => port.to_owned(),
        }
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreserved(port) => write!(f, "{}", port)?,
            Self::Reserved(pg) => write!(f, "{}", pg.port_number())?,
        }
        Ok(())
    }
}

pub enum PortGuardError {
    Placeholder,
}

// Holds the fd of a reservation socket and the reserved port number
// The socket needs to remain in scope for the port it was assigned to stay reserved for our process.
// Reservation sockets allow us to either request a free port from the kernel or guarantee that a
// client provided port is free
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortGuard {
    pub sock_fd: i32,
    pub port: u16,
    is_tcp: bool,
}

impl PortGuard {
    pub fn new(request_port: u16, is_tcp_port: bool) -> Result<Self, PortGuardError> {
        let (fd, port) =
            socket::new_reservation_sock(request_port).map_err(|_| PortGuardError::Placeholder)?;

        let pg = Self {
            sock_fd: fd,
            port: port,
            is_tcp: is_tcp_port,
        };

        if is_tcp_port {
            match os::switch_iptables_kernel_rst_block(port, os::IpTableRuleAction::Insert) {
                Ok(true) => {
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

    pub fn port_number(&self) -> u16 {
        self.port
    }
}

impl TryFrom<&Port> for PortGuard {
    type Error = PortGuardError;
    fn try_from(value: &Port) -> Result<Self, Self::Error> {
        match value {
            Port::Reserved(pg) => Ok(pg.clone()),
            Port::Unreserved(_) => Err(PortGuardError::Placeholder),
        }
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
        unsafe {
            libc::close(self.sock_fd);
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
    CouldNotResolveHost,
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
        let res: Option<Vec<u8>>;

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
            res = Some(
                (0..str_split.len())
                    .map(|i| {
                        u8::from_str_radix(&str_split[i], 16)
                            .map_err(|_| AddressError::ConvertionFailed)
                    })
                    .collect::<Result<Vec<u8>, AddressError>>()?,
            );
        // XXXXXXXXXXXX
        } else {
            res = Some(
                (0..str_no_term_char.len())
                    .step_by(2)
                    .map(|i| {
                        u8::from_str_radix(&str_no_term_char[i..i + 1], 16)
                            .map_err(|_| AddressError::ConvertionFailed)
                    })
                    .collect::<Result<Vec<u8>, AddressError>>()?,
            );
        }

        match res {
            Some(bytes) => {
                if bytes.len() != 6 {
                    return Err(AddressError::NotEnoughOctets);
                } else {
                    let mut byte_array: [u8; 6] = [0; 6];
                    byte_array.copy_from_slice(&bytes);

                    return Ok(MacAddress(byte_array));
                }
            }
            None => return Err(AddressError::ConvertionFailed),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockAddrV4(pub IPv4Address, pub Port);

impl SockAddrV4 {
    pub fn addr(&self) -> IPv4Address {
        self.0
    }

    pub fn port(&self) -> Port {
        self.1.clone()
    }
}
impl fmt::Display for SockAddrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IP: {} | Port: {}", self.addr(), self.port())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockAddrV6(pub IPv6Address, pub Port);

impl SockAddrV6 {
    pub fn addr(&self) -> IPv6Address {
        self.0
    }

    pub fn port(&self) -> Port {
        self.1.clone()
    }
}

impl fmt::Display for SockAddrV6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IP: {} | Port: {}", self.addr(), self.port())
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

    pub fn port(&self) -> Port {
        match self {
            Self::V4(addr) => addr.port(),
            Self::V6(addr) => addr.port(),
        }
    }
}

impl fmt::Display for SockAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SockAddr::V4(addr) => write!(f, "{}", addr)?,
            SockAddr::V6(addr) => write!(f, "{}", addr)?,
        }
        Ok(())
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
    fn to_sock_addr(&self) -> Result<SockAddr, AddressError>;
}

impl ToSockAddr for &str {
    fn to_sock_addr(&self) -> Result<SockAddr, AddressError> {
        // TODO: Handle IPv6
        // TODO: Possibly need to handle this being used for local addresses wherein ports will need
        // to be reserved e.g listeners

        let port: u16;
        let addr: &str;

        match self.split_once(":") {
            Some(split) => {
                let p = split
                    .1
                    .parse::<u16>()
                    .map_err(|_| AddressError::InvalidPort)?;

                port = p;
                addr = split.0;
            }
            None => return Err(AddressError::InvalidAddress),
        }

        let is_ip = is_valid_ipv4(addr);
        // subdomain.domain.com
        // domain.com
        // d0m41n.com
        let is_host_name = is_valid_hostname(addr);

        if !is_ip & !is_host_name {
            return Err(AddressError::InvalidAddress);
        }

        if is_ip {
            let ip = IPv4Address::try_from(addr).map_err(|_| AddressError::InvalidAddress)?;

            return Ok(SockAddr::V4(SockAddrV4(ip, Port::Unreserved(port))));
        } else {
            let ip = resolve_domain_name(addr).map_err(|_| AddressError::CouldNotResolveHost)?;

            let ip_v4 =
                IPv4Address::try_from(ip.as_slice()).map_err(|_| AddressError::InvalidAddress)?;

            return Ok(SockAddr::V4(SockAddrV4(ip_v4, Port::Unreserved(port))));
        }
    }
}
fn is_valid_ipv4(s: &str) -> bool {
    let mut parts = s.split('.');

    for _ in 0..4 {
        match parts.next() {
            Some(part) => {
                // Octect is not empty, has less than 3 chars and all chars are digits
                if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
                    return false;
                }
                // Octet not greater than 255
                match part.parse::<u8>() {
                    Ok(_) => {}
                    Err(_) => return false,
                }
            }
            None => return false,
        }
    }

    if parts.next().is_some() {
        return false; // more than four parts
    }
    true
}

fn is_valid_hostname(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
