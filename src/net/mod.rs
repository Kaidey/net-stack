pub mod com;
pub mod socket;

use libc::{c_void, recv, send};

use crate::net::com::{
    address::{HardwareAddress, IPv4Address, MacAddress, ProtocolAddress},
    arp,
    ethernet::Frame,
};

use crate::net::com::{ethernet, ipv4, tcp};
// use crate::net::com::{address, arp, ethernet, ipv4, run_arp, tcp};
use crate::os;

// TODO: Impl TcpListener

pub struct TcpConnection {
    sock_fd: i32,
    dest_ip: [u8; 4],
    dest_port: u16,
}

#[derive(Debug)]
pub enum TcpError {
    InvalidPort,
    InvalidAddress,
    MalformedAddressString,
    GetSourceIp,
    GetSourceMac,
    GetGatewayIp,
    ArpFailed,
    Handshake,
}

impl TcpConnection {
    pub fn new(dest_addr: &str) -> Result<Self, TcpError> {
        // Parse remote IPv4 addr and port
        // TODO: DNS resolution
        let slices = dest_addr.split(":").collect::<Vec<&str>>();

        if slices.len() != 2 || slices[1].is_empty() {
            return Err(TcpError::MalformedAddressString);
        }

        let dest_ip =
            com::address::IPv4Address::try_from(slices[0]).map_err(|_| TcpError::InvalidAddress)?;

        // Radix is the same as the base of the number system we want to use (base 10 here)
        let radix: u32 = 10;

        // TODO: Get digits from port string
        // let dest_port_digits: Vec<u32> = slices[1]
        //     .chars()
        //     .map(|c| c.to_digit(radix))
        //     .collect::<Option<Vec<u32>>>()
        //     .ok_or(TcpError::InvalidPort)?;

        // let src_port_digits: Vec<u32> = slices[1]
        //     .chars()
        //     .map(|c| c.to_digit(radix))
        //     .collect::<Option<Vec<u32>>>()
        //     .ok_or(TcpError::InvalidPort)?;

        let target_itf = os::get_active_wifi_interface()
            .unwrap()
            .first()
            .unwrap()
            .to_owned();

        // Get IPv4 addr of net interface target_itf
        let src_ip_res: Option<[u8; 4]> =
            os::get_itf_ipv4_addr(&target_itf).map_err(|_| TcpError::GetSourceIp)?;
        let src_ip = match src_ip_res {
            Some(ip) => {
                IPv4Address::try_from(ip.as_slice()).or_else(|_| Err(TcpError::GetSourceIp))?
            }
            None => return Err(TcpError::GetSourceIp),
        };

        // Get MAC addr of net interface target_itf
        let src_mac_res: Option<String> =
            os::get_itf_mac_addr(&target_itf).map_err(|_| TcpError::GetSourceMac)?;
        let src_mac = match src_mac_res {
            Some(mac) => {
                MacAddress::try_from(mac.as_str()).or_else(|_| Err(TcpError::GetSourceMac))?
            }
            None => return Err(TcpError::GetSourceMac),
        };

        let sock_fd = socket::new_socket(&target_itf);
        let dest_mac;

        // TODO: Check if remote IP is LAN
        let is_lan = false;

        if is_lan {
            // If LAN -> ARP for remote IP and use remote MAC
            let dest_mac_bytes =
                run_arp(sock_fd, src_mac.clone(), src_ip.clone(), dest_ip.clone()).unwrap();
            dest_mac =
                MacAddress::try_from(dest_mac_bytes.as_slice()).map_err(|_| TcpError::ArpFailed)?;
        } else {
            // If not LAN -> ARP for default gateway IP and use gateway MAC
            let gateway_ip_res = os::get_default_gateway_ipv4_addr();

            match gateway_ip_res {
                Ok(res) => match res {
                    Some(ip_bytes) => {
                        let gateway_ip = IPv4Address::try_from(ip_bytes.as_slice())
                            .map_err(|_| TcpError::GetGatewayIp)?;

                        let dest_mac_bytes =
                            run_arp(sock_fd, src_mac.clone(), src_ip.clone(), gateway_ip.clone())
                                .unwrap();

                        dest_mac = MacAddress::try_from(dest_mac_bytes.as_slice())
                            .map_err(|_| TcpError::ArpFailed)?;
                    }
                    None => return Err(TcpError::GetGatewayIp),
                },
                Err(_) => return Err(TcpError::GetGatewayIp),
            }
        }

        if dest_mac == MacAddress::all_zero() {
            return Err(TcpError::ArpFailed);
        }

        tcp_handshake(sock_fd, src_mac, dest_mac, src_ip, dest_ip, 0xFDE8, 0x0050).unwrap();

        Err(TcpError::InvalidAddress)
    }
}

// TODO: Investigate overuse of .clone()
pub fn tcp_handshake(
    sock_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    src_ip: IPv4Address,
    dest_ip: IPv4Address,
    src_port: u16,
    dest_port: u16,
) -> Result<bool, TcpError> {
    let tcp_segment = tcp::Segment::new(
        src_ip,
        src_port,
        dest_ip,
        dest_port,
        tcp::Flags::SYN,
        vec![],
    )
    .map_err(|_| TcpError::Handshake)?
    .checksum(src_ip, dest_ip, tcp::Segment::CODEPOINT)
    .map_err(|_| TcpError::Handshake)?;

    let ip_datagram = ipv4::Datagram::<tcp::Segment>::new(src_ip, dest_ip, tcp_segment)
        .map_err(|_| TcpError::Handshake)?
        .checksum()
        .map_err(|_| TcpError::Handshake)?;

    let frame = ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::new(
        dest_mac.clone(),
        src_mac.clone(),
        ip_datagram,
    );

    let frame_as_bytes: Vec<u8> = Vec::try_from(&frame).map_err(|_| TcpError::Handshake)?;

    let bytes_sent = unsafe {
        send(
            sock_fd,
            frame_as_bytes.as_ptr() as *const _,
            frame_as_bytes.len(),
            0,
        )
    };
    println!("SYN Sent:\n {}", frame);

    if bytes_sent < 0 {
        return Err(TcpError::Handshake);
    }
    let mut buffer = [0u8; 65536];

    // TODO
    // Handle reply not being received
    // threads?
    // Retries with limit wait time?
    loop {
        let frame_size =
            unsafe { recv(sock_fd, buffer.as_mut_ptr() as *mut c_void, buffer.len(), 0) };

        if frame_size < 0 {
            return Err(TcpError::Handshake);
        }

        let eth_type = u16::from_be_bytes([buffer[12], buffer[13]]);

        match eth_type {
            // TODO: Review, maybe swap to Enum
            0x0800 => {
                // Ethernet frame has 14 bytes of header. Next proto field is byte 10 (9 index) of an IPv4
                // header
                let next_proto_cp = buffer[14 + 9];
                match next_proto_cp {
                    tcp::Segment::CODEPOINT => {
                        let frame = ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::try_from(
                            buffer.as_slice(),
                        )
                        .map_err(|_| TcpError::Handshake)?;

                        let eth_payload: &ipv4::Datagram<tcp::Segment> = &frame.payload;
                        let ip_payload: &tcp::Segment = &eth_payload.payload;

                        if eth_payload.src_ip == dest_ip
                            && eth_payload.dest_ip == src_ip
                            && ip_payload.dest_port == src_port
                            && ip_payload.src_port == dest_port
                        {
                            println!("\n\nRemote ACK SYN:\n {}", frame);

                            let resp_tcp_segment = tcp::Segment::new(
                                src_ip,
                                src_port,
                                dest_ip,
                                dest_port,
                                tcp::Flags::ACK,
                                vec![],
                            )
                            .map_err(|_| TcpError::Handshake)?
                            .seq(ip_payload.ack_num)
                            .ack(ip_payload.seq_num + 1)
                            .checksum(src_ip, dest_ip, tcp::Segment::CODEPOINT)
                            .map_err(|_| TcpError::Handshake)?;

                            let resp_ipv4_datagram = ipv4::Datagram::<tcp::Segment>::new(
                                src_ip,
                                dest_ip,
                                resp_tcp_segment,
                            )
                            .map_err(|_| TcpError::Handshake)?
                            .checksum()
                            .map_err(|_| TcpError::Handshake)?;

                            let resp_frame = ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::new(
                                dest_mac.clone(),
                                src_mac.clone(),
                                resp_ipv4_datagram,
                            );

                            let resp_frame_as_bytes: Vec<u8> =
                                Vec::try_from(&resp_frame).map_err(|_| TcpError::Handshake)?;

                            let bytes_sent = unsafe {
                                send(
                                    sock_fd,
                                    resp_frame_as_bytes.as_ptr() as *const _,
                                    resp_frame_as_bytes.len(),
                                    0,
                                )
                            };

                            println!("\n\nACK Sent:\n {}", resp_frame);

                            if bytes_sent < 0 {
                                return Err(TcpError::Handshake);
                            }
                            let mut buffer = [0u8; 65536];

                            loop {
                                let frame_size = unsafe {
                                    recv(
                                        sock_fd,
                                        buffer.as_mut_ptr() as *mut c_void,
                                        buffer.len(),
                                        0,
                                    )
                                };

                                if frame_size < 0 {
                                    return Err(TcpError::Handshake);
                                }

                                let eth_type = u16::from_be_bytes([buffer[12], buffer[13]]);

                                match eth_type {
                                    // TODO: Review, maybe swap to Enum
                                    0x0800 => {
                                        // Ethernet frame has 14 bytes of header. Next proto field is byte 10 (9 index) of an IPv4
                                        // header
                                        let next_proto_cp = buffer[14 + 9];
                                        match next_proto_cp {
                                            tcp::Segment::CODEPOINT => {
                                                let frame = ethernet::Frame::<
                                                    ipv4::Datagram<tcp::Segment>,
                                                >::try_from(
                                                    buffer.as_slice()
                                                )
                                                .map_err(|_| TcpError::Handshake)?;
                                                println!(
                                                    "\n\nHANDSHAKE DONE!!!\nFinal Frame from remote:\n {}",
                                                    frame
                                                );
                                                return Ok(true);
                                            }
                                            _ => {}
                                        };
                                    }
                                    _ => {}
                                };
                            }
                        }
                    }
                    _ => {}
                };
            }
            _ => {}
        };
    }
}

pub fn run_arp(
    socket_fd: i32,
    src_mac: MacAddress,
    src_ip: IPv4Address,
    dest_ip: IPv4Address,
) -> Option<[u8; 6]> {
    // TODO: Error handling
    let arp_datagram = arp::Datagram::new(
        HardwareAddress::MAC(src_mac.clone()),
        HardwareAddress::MAC(MacAddress::all_zero()),
        ProtocolAddress::IPv4(src_ip.clone()),
        ProtocolAddress::IPv4(dest_ip.clone()),
        arp::Operation::REQUEST,
    );

    let outbound_frame = Frame::<arp::Datagram>::new(MacAddress::broadcast(), src_mac, arp_datagram);

    let frame_as_bytes = Vec::try_from(&outbound_frame).expect("Wrong");

    let bytes_sent = unsafe {
        send(
            socket_fd,
            frame_as_bytes.as_ptr() as *const _,
            frame_as_bytes.len(),
            0,
        )
    };

    if bytes_sent < 0 {
        println!(
            "Failed to send ARP request: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut buffer = [0u8; 65536];

    // TODO
    // Handle reply not being received
    // threads?
    // Retries with limit wait time?
    loop {
        let frame_size = unsafe {
            recv(
                socket_fd,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                0,
            )
        };

        if frame_size < 0 {
            panic!("Error receiving frame: {}", std::io::Error::last_os_error());
        }

        let eth_type = u16::from_be_bytes([buffer[12], buffer[13]]);

        match eth_type {
            // TODO: Review, maybe swap to Enum
            0x0806 => {
                let inbound_frame = Frame::<arp::Datagram>::try_from(buffer.as_slice()).ok()?;

                if inbound_frame.payload.src_proto_addr == outbound_frame.payload.dest_proto_addr
                    && inbound_frame.payload.op == arp::Operation::REPLY
                {
                    let mut target_mac = [0; 6];
                    target_mac
                        .copy_from_slice(inbound_frame.payload.src_hardware_addr.addr_bytes());
                    return Some(target_mac);
                }
            }
            _ => {}
        };
    }
}
