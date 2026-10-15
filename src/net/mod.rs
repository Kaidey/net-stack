pub mod com;
pub mod socket;

use libc;

use std::time::{Duration, Instant};

use libc::{c_void, recv, send};

use crate::net::{
    com::{
        address::{
            HardwareAddress, IPv4Address, IPv6Address, IpAddr, MacAddress, ProtocolAddress,
            SockAddr, ToSockAddr,
        },
        arp,
        ethernet::Frame,
    },
    socket::{reserve_tcp_port, set_tcp_sock_timeout},
};

use crate::net::com::{ethernet, ipv4, tcp};
use crate::os;

const TIME_WAIT: Duration = Duration::from_secs(60);

// Holds the fd of a reservation socket and the reserved port number
// The socket needs to remain in scope for the port it was assigned to stay reserved for our process.
// Reservation sockets allow us to either request a free port from the kernel or guarantee that a
// client provided port is free
struct PortGuard {
    sock_fd: i32,
    port: u16,
}

impl PortGuard {
    fn new(request_port: u16) -> Result<Self, TcpError> {
        let (fd, port) = reserve_tcp_port(request_port).map_err(|_| TcpError::Placeholder)?;
        match os::switch_iptables_kernel_rst_block(port, os::IpTableRuleAction::Insert) {
            Ok(true) => Ok(Self {
                sock_fd: fd,
                port: port,
            }),
            _ => {
                unsafe {
                    libc::close(fd);
                }
                Err(TcpError::Placeholder)
            }
        }
    }
}

// Implements behaviour for when a value is dropped (goes out of scope)
// E.g: if an object holding a PortGuard type is dropped
impl Drop for PortGuard {
    fn drop(&mut self) {
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
        unsafe {
            libc::close(self.sock_fd);
        }
    }
}

pub struct TcpConnection {
    sock_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    src_sock_addr: SockAddr,
    dest_sock_addr: SockAddr,
    seq_num: u32,
    ack_num: u32,
    state: TcpState,
    time_wait_deadline: Option<std::time::Instant>,
    //
    src_port_guard: PortGuard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    CloseWait,
    LastAck,
    // Waiting for ACK to sent FIN
    FinWait1,
    // Waiting for matching FIN
    FinWait2,
    Closing,
    // TODO: Termination done, waiting to ensure sent ACK is received
    TimeWait,
}

#[derive(Debug)]
pub enum TcpError {
    InvalidAddress,
    GetSourceIp,
    GetSourceMac,
    GetGatewayIp,
    GetDestMac,
    ArpFailed,
    Handshake,
    UnclosedConnection,
    CloseConnectionFailed,
    Placeholder,
    SourceDestIpTypeMismatch,
    NotImplemented,
}

impl TcpConnection {
    pub fn new<T: ToSockAddr>(dest_addr: T, src_port: Option<u16>) -> Result<Self, TcpError> {
        // Create socket and bind to active interface
        let target_itf = os::get_active_wifi_interface()
            .unwrap()
            .first()
            .unwrap()
            .to_owned();

        let sock_fd = socket::new_socket(&target_itf);

        // Get MAC addr of net interface target_itf
        let src_mac_res: Option<String> =
            os::get_itf_mac_addr(&target_itf).map_err(|_| TcpError::GetSourceMac)?;
        let src_mac = match src_mac_res {
            Some(mac) => MacAddress::try_from(mac.as_str()).map_err(|_| TcpError::GetSourceMac)?,
            None => return Err(TcpError::GetSourceMac),
        };

        let dest_sock_addr = dest_addr
            .to_sock_addr()
            .map_err(|_| TcpError::InvalidAddress)?;

        let mut src_ip: Option<IpAddr> = None;

        // Source IP should match the type of the dest IP (4 or 6)
        match dest_sock_addr.ip_addr() {
            IpAddr::V4(_) => {
                // Get IPv4 addr of net interface target_itf
                let itf_ip_res: Option<[u8; 4]> =
                    os::get_itf_ipv4_addr(&target_itf).map_err(|_| TcpError::GetSourceIp)?;
                match itf_ip_res {
                    Some(itf_ip) => {
                        let ip_addr = IPv4Address::try_from(itf_ip.as_slice());

                        match ip_addr {
                            Ok(addr) => src_ip = Some(IpAddr::V4(addr)),
                            Err(_) => return Err(TcpError::GetSourceIp),
                        }
                    }
                    None => return Err(TcpError::GetSourceIp),
                };
            }
            IpAddr::V6(_) => {}
        }

        // If we were successfull in computing our src_ip, compute dest_mac and establish connection
        match src_ip {
            Some(src_ip_addr) => {
                let res = compute_dest_mac(sock_fd, src_mac, src_ip_addr, dest_sock_addr.ip_addr());

                match res {
                    Ok(dest_mac) => {
                        let port = src_port.unwrap_or(0);
                        let src_port_guard = PortGuard::new(port)?;

                        let mut conn = Self {
                            src_mac: src_mac,
                            dest_mac: dest_mac,
                            sock_fd: sock_fd,
                            src_sock_addr: SockAddr(src_ip_addr, src_port_guard.port),
                            dest_sock_addr: dest_sock_addr,
                            seq_num: 0,
                            ack_num: 0,
                            state: TcpState::Closed,
                            time_wait_deadline: None,
                            src_port_guard: src_port_guard,
                        };

                        let hdsk_res = conn.handshake();
                        match hdsk_res {
                            Ok(_) => {
                                if conn.state == TcpState::Established {
                                    println!("Handshake completed! {:?}", conn.state);
                                    return Ok(conn);
                                } else {
                                    return Err(TcpError::Handshake);
                                }
                            }
                            Err(_) => return Err(TcpError::Handshake),
                        }
                    }
                    Err(_) => return Err(TcpError::GetDestMac),
                }
            }
            None => return Err(TcpError::GetSourceIp),
        }
    }

    pub fn close(mut self) -> Result<(), TcpError> {
        let fin_res = send_fin(
            self.sock_fd,
            self.src_mac,
            self.dest_mac,
            self.src_sock_addr.ip_addr(),
            self.dest_sock_addr.ip_addr(),
            self.src_sock_addr.port(),
            self.dest_sock_addr.port(),
            self.seq_num,
            self.ack_num,
        );

        match fin_res {
            Ok(_) => {
                self.state = TcpState::FinWait1;
                // FIN consumes a byte in the byte stream, so our seq_num needs to be incremented
                self.seq_num = self.seq_num.wrapping_add(1);
            }
            Err(_) => return Err(TcpError::CloseConnectionFailed),
        }

        let mut buffer = [0u8; 65536];

        while self.state != TcpState::Closed {
            // The following block is responsible for transitioning the connection from TimeWait to
            // Closed and also guaranteeing that, if no other frames arrive at the socket, the recv
            // call will only hang until the deadline is reached, at which point control is given
            // back to the program by the kernel (recv blocks the thread until it has something to
            // return - a new frame arrived. If no timeout is specified - 0 default -, it hangs indefinitely)
            //
            // Also important, the reason this calculation is done in every iteration is
            // because, since we're using raw sockets, frames not related to this TCP Connection
            // might be returned by recv which have no effect on it, but time towards the deadline
            // still needs to advance while they are parsed. Otherwise, it would only advance when
            // we received another frame related to this connection, which likely would never happen
            // in TimeWait

            // If self has a value assigned to time_wait_remaining, meaning the connection has
            // entered TimeWait state
            if let Some(dl) = self.time_wait_deadline {
                let now = std::time::Instant::now();
                // If the deadline for the TimeWait state has passed, close the connection
                if now >= dl {
                    self.state = TcpState::Closed;
                    println!("TCP Connection Closed!!");
                    break;
                }
                let time_before_deadline = dl - now;
                // Update socket timeout to reflect how much time is left before the TimeWait
                // deadline is reached
                set_tcp_sock_timeout(self.sock_fd, time_before_deadline)
                    .map_err(|_| TcpError::CloseConnectionFailed)?;
            }
            let frame_size = unsafe {
                recv(
                    self.sock_fd,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len(),
                    0,
                )
            };

            // If recv hangs (no new frames) and the timeout we set is reached, frame_size will be -1 which continues the listening loop as intended
            if frame_size < 0 {
                continue;
            }

            let eth_type = u16::from_be_bytes([buffer[12], buffer[13]]);
            // Ethernet frame has 14 bytes of header. Next proto field is byte 10 (9 index) of an IPv4
            // header
            let next_proto_cp = buffer[14 + 9];

            match eth_type {
                ipv4::CODEPOINT => match next_proto_cp {
                    tcp::CODEPOINT => {
                        let frame = ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::try_from(
                            &buffer[..frame_size as usize],
                        );

                        match frame {
                            Ok(frame) => {
                                let remote_ip_dgram: &ipv4::Datagram<tcp::Segment> = &frame.payload;
                                let remote_tcp_seg: &tcp::Segment = &remote_ip_dgram.payload;

                                let is_from_remote = remote_ip_dgram.src_ip.addr_bytes()
                                    == self.dest_sock_addr.ip_addr().addr_bytes()
                                    && remote_ip_dgram.dest_ip.addr_bytes()
                                        == self.src_sock_addr.ip_addr().addr_bytes()
                                    && remote_tcp_seg.dest_port == self.src_sock_addr.port()
                                    && remote_tcp_seg.src_port == self.dest_sock_addr.port();

                                if is_from_remote {
                                    // All segments after handshake are expected to contain the ACK flag and
                                    // a valid ACK number
                                    //
                                    // What differentiates a FIN,ACK where the remote is ACKing my FIN and
                                    // sending its own and a FIN,ACK that is just the remote's FIN
                                    // is the value of the actual ack number
                                    //
                                    // If the ack number is my FINs seq number + 1, then the server
                                    // acknowledged my FIN and is responding with its own
                                    // If it is my FIN's seq number or anything below seq_num + 1, then my FIN wasn't
                                    // acknowledged and the remote is just sending its own

                                    let is_remote_fin =
                                        remote_tcp_seg.flags.contains(tcp::Flags::FIN);
                                    let is_ack_of_sent_fin = remote_tcp_seg.ack_num == self.seq_num;

                                    // In the below logic, a re-transmitted FIN while in TimeWait
                                    // will not match any if branch but the ACK will still be sent
                                    // for said FIN.
                                    // There are no state changes and, thus, eventually wait time is over
                                    // and the connection transitions to closed, as expected
                                    if is_remote_fin {
                                        let mut new_state = self.state;
                                        // Use wrapping_add since the raw sum might end up being
                                        // higher than the max u32
                                        let new_ack = remote_tcp_seg
                                            .seq_num
                                            .wrapping_add(remote_tcp_seg.payload.len() as u32)
                                            .wrapping_add(1);

                                        // If the seq_num from the FIN does not match my ack (the
                                        // next seq I expect from the remote) either due to a
                                        // FIN re-transmit (my ack has already been updated but
                                        // remote's seq is lower) or
                                        // payload bytes that haven't been received yet (my ack
                                        // hasn't been updated and remote's seq is higher)
                                        if remote_tcp_seg.seq_num == self.ack_num {
                                            // Remote FIN and ACK of sent FIN in separate segments
                                            // No need to check for ack value because to be in FinWait2 means
                                            // that my FIN was already ACKed so is_ack_of_sent_fin will always
                                            // be true
                                            // TODO: Handle possible data transmition while in FinWait1 and
                                            // FinWait2
                                            if self.state == TcpState::FinWait2 {
                                                new_state = TcpState::TimeWait;
                                            }
                                            // Remote FIN and ACK of sent FIN on the same segment
                                            else if is_ack_of_sent_fin
                                                && self.state == TcpState::FinWait1
                                            {
                                                println!(
                                                    "FIN,ACK received, transition to TimeWait"
                                                );
                                                new_state = TcpState::TimeWait;
                                            }
                                            // Simultaenous Close - remote FIN received before my FIN is ACKed
                                            else if !is_ack_of_sent_fin
                                                && self.state == TcpState::FinWait1
                                            {
                                                new_state = TcpState::Closing;
                                            }

                                            self.ack_num = new_ack;
                                        }

                                        send_ack(
                                            self.sock_fd,
                                            self.src_mac,
                                            self.dest_mac,
                                            self.src_sock_addr.ip_addr(),
                                            self.dest_sock_addr.ip_addr(),
                                            self.src_sock_addr.port(),
                                            self.dest_sock_addr.port(),
                                            self.seq_num,
                                            self.ack_num,
                                        )
                                        .map_err(|_| TcpError::CloseConnectionFailed)?;

                                        self.state = new_state;

                                        // Only start the timer if the seq_num is the expected or it
                                        // is a retransmit
                                        if new_state == TcpState::TimeWait {
                                            self.time_wait_deadline =
                                                Some(Instant::now() + TIME_WAIT);
                                        }
                                    } else {
                                        if is_ack_of_sent_fin && self.state == TcpState::FinWait1 {
                                            self.state = TcpState::FinWait2;
                                        } else if is_ack_of_sent_fin
                                            && self.state == TcpState::Closing
                                        {
                                            self.state = TcpState::TimeWait;
                                            self.time_wait_deadline =
                                                Some(Instant::now() + TIME_WAIT);
                                        }
                                    }
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        return Ok(());
    }

    pub fn handshake(&mut self) -> Result<(), TcpError> {
        let syn_res = send_syn(
            self.sock_fd,
            self.src_mac,
            self.dest_mac,
            self.src_sock_addr.ip_addr(),
            self.dest_sock_addr.ip_addr(),
            self.src_sock_addr.port(),
            self.dest_sock_addr.port(),
        );

        match syn_res {
            Ok(isn) => {
                self.state = TcpState::SynSent;
                self.seq_num = isn.wrapping_add(1)
            }
            Err(_) => return Err(TcpError::Handshake),
        }
        let mut buffer = [0u8; 65536];

        while self.state != TcpState::Established && self.state != TcpState::Closed {
            let frame_size = unsafe {
                recv(
                    self.sock_fd,
                    buffer.as_mut_ptr() as *mut c_void,
                    buffer.len(),
                    0,
                )
            };

            if frame_size < 0 {
                return Err(TcpError::Handshake);
            }

            let eth_type = u16::from_be_bytes([buffer[12], buffer[13]]);
            // Ethernet frame has 14 bytes of header. Next proto field is byte 10 (9 index) of an IPv4
            // header
            let next_proto_cp = buffer[14 + 9];

            match eth_type {
                // TODO: Rethink this. self.dest_sock_addr and self.src_sock_addr could be IPv6 and
                // we will still parse IPv4 traffic. This approach works because in this case
                // is_syn_from_remote will always evaluate to false, but it bugs me semantically
                ipv4::CODEPOINT => match next_proto_cp {
                    tcp::CODEPOINT => {
                        let frame = ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::try_from(
                            &buffer[..frame_size as usize],
                        )
                        .map_err(|_| TcpError::Handshake)?;

                        let remote_ip_dgram: &ipv4::Datagram<tcp::Segment> = &frame.payload;
                        let remote_tcp_seg: &tcp::Segment = &remote_ip_dgram.payload;

                        let is_syn_from_remote = remote_ip_dgram.src_ip.addr_bytes()
                            == self.dest_sock_addr.ip_addr().addr_bytes()
                            && remote_ip_dgram.dest_ip.addr_bytes()
                                == self.src_sock_addr.ip_addr().addr_bytes()
                            && remote_tcp_seg.dest_port == self.src_sock_addr.port()
                            && remote_tcp_seg.src_port == self.dest_sock_addr.port()
                            && remote_tcp_seg.flags.contains(tcp::Flags::SYN);

                        let is_ack_to_syn = remote_tcp_seg.ack_num == self.seq_num;

                        if is_syn_from_remote {
                            if is_ack_to_syn == false {
                                return Err(TcpError::UnclosedConnection);
                            }

                            // A SYN can't carry any payload so, unlike sending an ACK to a FIN, here we
                            // only add 1 to the remote's seq_num and don't assume any payload length
                            let new_ack = remote_tcp_seg.seq_num.wrapping_add(1);

                            self.ack_num = new_ack;

                            let ack_res = send_ack(
                                self.sock_fd,
                                self.src_mac,
                                self.dest_mac,
                                self.src_sock_addr.ip_addr(),
                                self.dest_sock_addr.ip_addr(),
                                self.src_sock_addr.port(),
                                self.dest_sock_addr.port(),
                                self.seq_num,
                                self.ack_num,
                            );

                            match ack_res {
                                Ok(_) => {
                                    self.state = TcpState::Established;
                                }
                                Err(_) => return Err(TcpError::Handshake),
                            }
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        return Ok(());
    }
}

fn compute_dest_mac(
    sock_fd: i32,
    src_mac: MacAddress,
    src_ip: IpAddr,
    dest_ip: IpAddr,
) -> Result<MacAddress, TcpError> {
    match (src_ip, dest_ip) {
        (IpAddr::V4(src_ip_addr), IpAddr::V4(dest_ip_addr)) => {
            // TODO: Figure out if it's LAN addr
            let is_lan = false;

            if is_lan {
                // If LAN -> ARP for remote IP and use remote MAC
                let dest_mac_bytes = run_arp(sock_fd, src_mac, src_ip_addr, dest_ip_addr).unwrap();

                return Ok(MacAddress::try_from(dest_mac_bytes.as_slice())
                    .map_err(|_| TcpError::ArpFailed)?);
            } else {
                // If not LAN -> ARP for default gateway IP and use gateway MAC
                let gateway_ip_res = os::get_default_gateway_ipv4_addr();

                match gateway_ip_res {
                    Ok(res) => match res {
                        Some(ip_bytes) => {
                            let gateway_ip = IPv4Address::try_from(ip_bytes.as_slice())
                                .map_err(|_| TcpError::GetGatewayIp)?;

                            let dest_mac_bytes =
                                run_arp(sock_fd, src_mac, src_ip_addr, gateway_ip).unwrap();

                            return Ok(MacAddress::try_from(dest_mac_bytes.as_slice())
                                .map_err(|_| TcpError::ArpFailed)?);
                        }
                        // TODO: Review
                        None => return Err(TcpError::GetGatewayIp),
                    },
                    Err(_) => return Err(TcpError::GetGatewayIp),
                }
            }
        }
        // TODO: Implement Neighbour Discovery Protocol
        (IpAddr::V6(_src), IpAddr::V6(_dest)) => return Err(TcpError::Placeholder),
        _ => return Err(TcpError::SourceDestIpTypeMismatch),
    }
}

fn send_ack(
    socket_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    src_ip: IpAddr,
    dest_ip: IpAddr,
    src_port: u16,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
) -> Result<(), TcpError> {
    match (src_ip, dest_ip) {
        (IpAddr::V4(src_ipv4), IpAddr::V4(dest_ipv4)) => {
            let seg = tcp::Segment::new(
                src_ip,
                src_port,
                dest_ip,
                dest_port,
                tcp::Flags::ACK,
                vec![],
            )
            .map_err(|_| TcpError::Placeholder)?
            .seq(seq_num)
            .ack(ack_num)
            .checksum_ipv4(src_ipv4, dest_ipv4, tcp::CODEPOINT)
            .map_err(|_| TcpError::Placeholder)?;

            let dat = ipv4::Datagram::<tcp::Segment>::new(src_ipv4, dest_ipv4, seg.clone())
                .map_err(|_| TcpError::Placeholder)?
                .checksum()
                .map_err(|_| TcpError::Placeholder)?;

            let frame =
                ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::new(dest_mac, src_mac, dat);

            let resp_frame_as_bytes: Vec<u8> =
                Vec::try_from(&frame).map_err(|_| TcpError::Placeholder)?;

            let bytes_sent = unsafe {
                send(
                    socket_fd,
                    resp_frame_as_bytes.as_ptr() as *const _,
                    resp_frame_as_bytes.len(),
                    0,
                )
            };

            if bytes_sent < 0 {
                return Err(TcpError::Placeholder);
            }
            return Ok(());
        }
        (IpAddr::V6(_src), IpAddr::V6(_dest)) => return Err(TcpError::NotImplemented),
        _ => return Err(TcpError::SourceDestIpTypeMismatch),
    }
}

fn send_fin(
    socket_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    src_ip: IpAddr,
    dest_ip: IpAddr,
    src_port: u16,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
) -> Result<(), TcpError> {
    match (src_ip, dest_ip) {
        (IpAddr::V4(src_ipv4), IpAddr::V4(dest_ipv4)) => {
            let seg = tcp::Segment::new(
                src_ip,
                src_port,
                dest_ip,
                dest_port,
                tcp::Flags::FIN | tcp::Flags::ACK,
                vec![],
            )
            .map_err(|_| TcpError::CloseConnectionFailed)?
            .seq(seq_num)
            .ack(ack_num)
            .checksum_ipv4(src_ipv4, dest_ipv4, tcp::CODEPOINT)
            .map_err(|_| TcpError::CloseConnectionFailed)?;

            let dgram = ipv4::Datagram::<tcp::Segment>::new(src_ipv4, dest_ipv4, seg.clone())
                .map_err(|_| TcpError::CloseConnectionFailed)?
                .checksum()
                .map_err(|_| TcpError::CloseConnectionFailed)?;

            let frame =
                ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::new(dest_mac, src_mac, dgram);

            let frame_as_bytes: Vec<u8> =
                Vec::try_from(&frame).map_err(|_| TcpError::CloseConnectionFailed)?;

            let bytes_sent = unsafe {
                send(
                    socket_fd,
                    frame_as_bytes.as_ptr() as *const _,
                    frame_as_bytes.len(),
                    0,
                )
            };

            if bytes_sent < 0 {
                return Err(TcpError::CloseConnectionFailed);
            }
            return Ok(());
        }
        (IpAddr::V6(_src), IpAddr::V6(_dest)) => return Err(TcpError::NotImplemented),
        _ => return Err(TcpError::SourceDestIpTypeMismatch),
    }
}

fn send_syn(
    socket_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    src_ip: IpAddr,
    dest_ip: IpAddr,
    src_port: u16,
    dest_port: u16,
) -> Result<u32, TcpError> {
    match (src_ip, dest_ip) {
        (IpAddr::V4(src_ipv4), IpAddr::V4(dest_ipv4)) => {
            let seg = tcp::Segment::new(
                src_ip,
                src_port,
                dest_ip,
                dest_port,
                tcp::Flags::SYN,
                vec![],
            )
            .map_err(|_| TcpError::Handshake)?
            .checksum_ipv4(src_ipv4, dest_ipv4, tcp::CODEPOINT)
            .map_err(|_| TcpError::Handshake)?;

            let ip_datagram = ipv4::Datagram::<tcp::Segment>::new(src_ipv4, dest_ipv4, seg.clone())
                .map_err(|_| TcpError::Handshake)?
                .checksum()
                .map_err(|_| TcpError::Handshake)?;

            let frame = ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::new(
                dest_mac,
                src_mac,
                ip_datagram,
            );

            let frame_as_bytes: Vec<u8> = Vec::try_from(&frame).map_err(|_| TcpError::Handshake)?;

            let bytes_sent = unsafe {
                send(
                    socket_fd,
                    frame_as_bytes.as_ptr() as *const _,
                    frame_as_bytes.len(),
                    0,
                )
            };

            if bytes_sent < 0 {
                return Err(TcpError::Handshake);
            }
            // Returns the ISN generated for the SYN so it can be attached to the TCP Connection object by
            // the caller
            Ok(seg.seq_num)
        }
        (IpAddr::V6(_src), IpAddr::V6(_dest)) => return Err(TcpError::NotImplemented),
        _ => return Err(TcpError::SourceDestIpTypeMismatch),
    }
}

pub fn tcp_incoming_handler(segment: tcp::Segment) {

    // Drop malformed segments or segments without ACK

    // Handle incoming FIN

    // Handle incoming RST
    // Handle incoming SYN
    // Handle incoming others
}

pub fn run_arp(
    socket_fd: i32,
    src_mac: MacAddress,
    src_ip: IPv4Address,
    dest_ip: IPv4Address,
) -> Option<[u8; 6]> {
    // TODO: Error handling
    let arp_datagram = arp::Datagram::new(
        HardwareAddress::MAC(src_mac),
        HardwareAddress::MAC(MacAddress::ZERO),
        ProtocolAddress::IPv4(src_ip),
        ProtocolAddress::IPv4(dest_ip),
        arp::Operation::REQUEST,
    );

    let outbound_frame = Frame::<arp::Datagram>::new(MacAddress::BROADCAST, src_mac, arp_datagram);

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
            arp::CODEPOINT => {
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

// let http_payload = "GET / HTTP/1.1\r\nHost: scanme.nmap.org\r\nConnection: close\r\n\r\n".to_string().into_bytes();
//
// let http_tcp = tcp::Segment::new(
//     src_ip,
//     src_port,
//     dest_ip,
//     dest_port,
//     tcp::Flags::ACK | tcp::Flags::PSH,
//     http_payload,
// )
// .map_err(|_| TcpError::Handshake)?
// .seq(resp_tcp_segment.seq_num + 1)
// .ack(remote_tcp_seg.seq_num + 1)
// .checksum(src_ip, dest_ip, tcp::Segment::CODEPOINT)
// .map_err(|_| TcpError::Handshake)?;
//
// let http_ipv4 =
//     ipv4::Datagram::<tcp::Segment>::new(src_ip, dest_ip, http_tcp)
//         .map_err(|_| TcpError::Handshake)?
//         .checksum()
//         .map_err(|_| TcpError::Handshake)?;
//
// let http_frame =
//     ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::new(
//         dest_mac,
//         src_mac,
//         http_ipv4,
//     );
//
// let http_frame_as_bytes: Vec<u8> =
//     Vec::try_from(&resp_frame).map_err(|_| TcpError::Handshake)?;
//
// let bytes_sent = unsafe {
//     send(
//         sock_fd,
//         http_frame_as_bytes.as_ptr() as *const _,
//         http_frame_as_bytes.len(),
//         0,
//     )
// };
//
// println!("\n\nHTTP Sent:\n {}", http_frame);
//
// if bytes_sent < 0 {
//     return Err(TcpError::Handshake);
// }
