pub mod com;
pub mod socket;

use libc;

use std::time::{Duration, Instant};

use libc::{c_void, recv, send};

use crate::{
    net::com::{
        address::{
            HardwareAddress, IPv4Address, IPv6Address, MacAddress, PortGuard,
            ProtocolAddress, SockAddr, SockAddrV4, SockAddrV6, ToSockAddr,
        },
        arp, dns,
        ethernet::Frame,
        udp,
    },
    os::ItfAddrs,
};

use crate::net::com::{ethernet, ipv4, tcp};
use crate::os;

const TIME_WAIT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpError {
    Placeholder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionError {
    GetSourceIp,
    GetSourceMac,
    GetSourcePort,
    GetGatewayIp,
    GetDestMac,
    GetDestPort,
    ArpFailed,
    EndpointAddrFamilyMismatch,
    Placeholder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Helps guarantee that a TcpConnection cannot be created where dest and src addresses have an IP
// family mismatch
enum ConnectionEndpoints {
    V4(SockAddrV4, SockAddrV4),
    V6(SockAddrV6, SockAddrV6),
}

impl ConnectionEndpoints {
    fn get_addrs_bytes(self) -> (Vec<u8>, Vec<u8>) {
        match self {
            ConnectionEndpoints::V4(src, dest) => (
                src.addr().addr_bytes().to_vec(),
                dest.addr().addr_bytes().to_vec(),
            ),
            ConnectionEndpoints::V6(src, dest) => (
                src.addr().addr_bytes().to_vec(),
                dest.addr().addr_bytes().to_vec(),
            ),
        }
    }

    fn get_addrs_ports(self) -> (u16, u16) {
        match self {
            ConnectionEndpoints::V4(src, dest) => (src.port(), dest.port()),
            ConnectionEndpoints::V6(src, dest) => (src.port(), dest.port()),
        }
    }
}

pub struct TcpConnection {
    sock_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    conn_endpoints: ConnectionEndpoints,
    seq_num: u32,
    ack_num: u32,
    state: TcpState,
    time_wait_deadline: Option<std::time::Instant>,
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
    FailedToComputeConnEndpoints,
    Handshake,
    UnclosedConnection,
    CloseConnectionFailed,
    Placeholder,
    NotImplemented,
    InvalidDestAddress,
    FailedToComputeDestMac,
}

impl TcpConnection {
    pub fn new<T: ToSockAddr>(dest_addr: T, src_port: Option<u16>) -> Result<Self, TcpError> {
        let dest_sock_addr = dest_addr
            .to_sock_addr()
            .map_err(|_| TcpError::InvalidDestAddress)?;

        let (endpoints, target_itf, src_port_guard) = get_conn_4_tuple(dest_sock_addr.clone(), src_port, true)
            .map_err(|_| TcpError::FailedToComputeConnEndpoints)?;

        let itf_name = target_itf.get_itf_name();

        let sock_fd = socket::new_socket(itf_name);

        // Get MAC addr of net interface target_itf
        let src_mac_res: Option<String> = os::get_itf_mac_addr(itf_name)
            .map_err(|_| ConnectionError::GetSourceMac)
            .map_err(|_| TcpError::FailedToComputeConnEndpoints)?;
        let src_mac = match src_mac_res {
            Some(mac) => MacAddress::try_from(mac.as_str())
                .map_err(|_| ConnectionError::GetSourceMac)
                .map_err(|_| TcpError::FailedToComputeConnEndpoints)?,
            None => Err(ConnectionError::GetSourceMac)
                .map_err(|_| TcpError::FailedToComputeConnEndpoints)?,
        };

        let mut conn: Option<TcpConnection> = None;

        match dest_sock_addr {
            SockAddr::V4(sock_addr) => {
                let (src_addr_bytes, _) = endpoints.clone().get_addrs_bytes();

                let src_ipv4 = IPv4Address::try_from(src_addr_bytes.as_slice())
                    .map_err(|_| TcpError::FailedToComputeConnEndpoints)?;

                let dest_mac = compute_dest_mac_ipv4(sock_fd, src_mac, src_ipv4, sock_addr.addr())
                    .map_err(|_| ConnectionError::GetDestMac)
                    .map_err(|_| TcpError::FailedToComputeDestMac)?;

                conn = Some(Self {
                    src_mac: src_mac,
                    dest_mac: dest_mac,
                    sock_fd: sock_fd,
                    conn_endpoints: endpoints.clone(),
                    seq_num: 0,
                    ack_num: 0,
                    state: TcpState::Closed,
                    time_wait_deadline: None,
                    src_port_guard: src_port_guard 
                });
            }
            SockAddr::V6(_sock_addr) => {}
        }

        match conn {
            Some(mut c) => {
                let hdsk_res = c.handshake();
                match hdsk_res {
                    Ok(_) => {
                        if c.state == TcpState::Established {
                            println!("Handshake completed! {:?}", c.state);
                            return Ok(c);
                        } else {
                            return Err(TcpError::Handshake);
                        }
                    }
                    Err(_) => return Err(TcpError::Handshake),
                }
            }
            None => return Err(TcpError::Placeholder),
        }
    }

    pub fn close(mut self) -> Result<(), TcpError> {
        let fin_res = send_fin(
            self.sock_fd,
            self.src_mac,
            self.dest_mac,
            self.conn_endpoints.clone(),
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
                socket::set_tcp_sock_timeout(self.sock_fd, time_before_deadline)
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

                                let (self_src_addr_bytes, self_dest_addr_bytes) =
                                    self.conn_endpoints.clone().get_addrs_bytes();

                                let (self_src_addr_port, self_dest_addr_port) =
                                    self.conn_endpoints.clone().get_addrs_ports();

                                let is_from_remote = remote_ip_dgram.src_ip.addr_bytes()
                                    == self_dest_addr_bytes
                                    && remote_ip_dgram.dest_ip.addr_bytes() == self_src_addr_bytes
                                    && remote_tcp_seg.dest_port == self_src_addr_port
                                    && remote_tcp_seg.src_port == self_dest_addr_port;

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
                                            self.conn_endpoints.clone(),
                                            self.seq_num,
                                            self.ack_num,
                                            None
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

    fn handshake(&mut self) -> Result<(), TcpError> {
        let syn_res = send_syn(
            self.sock_fd,
            self.src_mac,
            self.dest_mac,
            self.conn_endpoints.clone(),
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

                        let (self_src_addr_bytes, self_dest_addr_bytes) =
                            self.conn_endpoints.clone().get_addrs_bytes();

                        let (self_src_addr_port, self_dest_addr_port) =
                            self.conn_endpoints.clone().get_addrs_ports();

                        let is_syn_from_remote = remote_ip_dgram.src_ip.addr_bytes()
                            == self_dest_addr_bytes
                            && remote_ip_dgram.dest_ip.addr_bytes() == self_src_addr_bytes
                            && remote_tcp_seg.dest_port == self_src_addr_port
                            && remote_tcp_seg.src_port == self_dest_addr_port;

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
                                self.conn_endpoints.clone(),
                                self.seq_num,
                                self.ack_num,
                                None
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

    pub fn send(&mut self, data: &[u8]) -> Result<(), TcpError> {
        let res = send_ack(
            self.sock_fd,
            self.src_mac,
            self.dest_mac,
            self.conn_endpoints.clone(),
            self.seq_num,
            self.ack_num,
            Some(data),
        );

        match res {
            Ok(_) => {
                self.seq_num = self.seq_num.wrapping_add(data.len() as u32);
            }
            Err(_) => return Err(TcpError::Placeholder),
        }

        Ok(())
    }
}

fn send_ack(
    socket_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    conn_endpoints: ConnectionEndpoints,
    seq_num: u32,
    ack_num: u32,
    data: Option<&[u8]>,
) -> Result<(), TcpError> {
    match conn_endpoints {
        ConnectionEndpoints::V4(src, dest) => {
            let src_generic = SockAddr::V4(src.clone());
            let dest_generic = SockAddr::V4(dest.clone());

            let payload: Vec<u8>;

            match data {
                Some(d) => payload = d.to_vec(),
                None => payload = vec![],
            }

            let seg = tcp::Segment::new(src_generic, dest_generic, tcp::Flags::ACK, payload)
                .map_err(|_| TcpError::Placeholder)?
                .seq(seq_num)
                .ack(ack_num)
                .checksum_ipv4(&src.addr(), &dest.addr(), tcp::CODEPOINT)
                .map_err(|_| TcpError::Placeholder)?;

            let dat = ipv4::Datagram::<tcp::Segment>::new(src.addr(), dest.addr(), seg.clone())
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
        ConnectionEndpoints::V6(_src, _dest) => return Err(TcpError::NotImplemented),
    }
}

fn send_fin(
    socket_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    conn_endpoints: ConnectionEndpoints,
    seq_num: u32,
    ack_num: u32,
) -> Result<(), TcpError> {
    match conn_endpoints {
        ConnectionEndpoints::V4(src, dest) => {
            let src_generic = SockAddr::V4(src.clone());
            let dest_generic = SockAddr::V4(dest.clone());

            let seg = tcp::Segment::new(
                src_generic,
                dest_generic,
                tcp::Flags::FIN | tcp::Flags::ACK,
                vec![],
            )
            .map_err(|_| TcpError::CloseConnectionFailed)?
            .seq(seq_num)
            .ack(ack_num)
            .checksum_ipv4(&src.addr(), &dest.addr(), tcp::CODEPOINT)
            .map_err(|_| TcpError::CloseConnectionFailed)?;

            let dgram = ipv4::Datagram::<tcp::Segment>::new(src.addr(), dest.addr(), seg.clone())
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
        ConnectionEndpoints::V6(_src, _dest) => return Err(TcpError::NotImplemented),
    }
}

fn send_syn(
    socket_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    conn_endpoints: ConnectionEndpoints,
) -> Result<u32, TcpError> {
    match conn_endpoints {
        ConnectionEndpoints::V4(src, dest) => {
            let src_generic = SockAddr::V4(src.clone());
            let dest_generic = SockAddr::V4(dest.clone());

            let seg = tcp::Segment::new(src_generic, dest_generic, tcp::Flags::SYN, vec![])
                .map_err(|_| TcpError::Handshake)?
                .checksum_ipv4(&src.addr(), &dest.addr(), tcp::CODEPOINT)
                .map_err(|_| TcpError::Handshake)?;

            let ip_datagram =
                ipv4::Datagram::<tcp::Segment>::new(src.addr(), dest.addr(), seg.clone())
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
        ConnectionEndpoints::V6(_src, _dest) => return Err(TcpError::NotImplemented),
    }
}

pub fn tcp_incoming_handler(_segment: tcp::Segment) {

    // Drop malformed segments or segments without ACK

    // Handle incoming FIN

    // Handle incoming RST
    // Handle incoming SYN
    // Handle incoming others
}

pub fn resolve_domain_name(domain_name: &str) -> Result<Vec<u8>, ConnectionError> {
    let dest_port = dns::PORT;

    let dest_ip = dns::Servers::GOOGLE.get_ipv4();

    let dest_sock_addr = SockAddr::V4(SockAddrV4(dest_ip, dest_port));

    let (endpoints, target_itf, _src_port_guard) =
        get_conn_4_tuple(dest_sock_addr, None, false).map_err(|_| ConnectionError::Placeholder)?;

    let itf_name = target_itf.get_itf_name();

    let sock_fd = socket::new_socket(itf_name);

    // Get MAC addr of net interface target_itf
    let src_mac_res: Option<String> =
        os::get_itf_mac_addr(itf_name).map_err(|_| ConnectionError::GetSourceMac)?;
    let src_mac = match src_mac_res {
        Some(mac) => {
            MacAddress::try_from(mac.as_str()).map_err(|_| ConnectionError::GetSourceMac)?
        }
        None => Err(ConnectionError::GetSourceMac)?,
    };

    let (src_ipv4_bytes, _) = endpoints.clone().get_addrs_bytes();
    let src_ipv4 = IPv4Address::try_from(src_ipv4_bytes.as_slice())
        .map_err(|_| ConnectionError::GetSourceIp)?;

    let dest_mac = compute_dest_mac_ipv4(sock_fd, src_mac, src_ipv4, dest_ip)
        .map_err(|_| ConnectionError::GetDestMac)?;

    let dns_query = dns::Message::query(domain_name).unwrap();

    let dns_query_as_bytes = Vec::try_from(&dns_query).map_err(|_| ConnectionError::Placeholder)?;

    send_udp(
        sock_fd,
        src_mac,
        dest_mac,
        endpoints.clone(),
        dns_query_as_bytes,
    )
    .map_err(|_| ConnectionError::Placeholder)?;

    let mut buffer = [0u8; 65536];

    let reply_received = false;

    let mut res = vec![];

    while !reply_received {
        let frame_size =
            unsafe { recv(sock_fd, buffer.as_mut_ptr() as *mut c_void, buffer.len(), 0) };

        if frame_size < 0 {
            return Err(ConnectionError::Placeholder);
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
                udp::CODEPOINT => {
                    let frame = ethernet::Frame::<ipv4::Datagram<udp::Segment>>::try_from(
                        &buffer[..frame_size as usize],
                    )
                    .map_err(|_| ConnectionError::Placeholder)?;

                    let remote_ip_dgram: &ipv4::Datagram<udp::Segment> = &frame.payload;
                    let remote_udp_seg: &udp::Segment = &remote_ip_dgram.payload;

                    let dns_reply = dns::Message::try_from(remote_udp_seg.payload.as_slice())
                        .map_err(|_| ConnectionError::Placeholder)?;

                    let (self_src_addr_bytes, self_dest_addr_bytes) =
                        endpoints.clone().get_addrs_bytes();

                    let (self_src_addr_port, self_dest_addr_port) =
                        endpoints.clone().get_addrs_ports();

                    let is_from_remote = remote_ip_dgram.src_ip.addr_bytes()
                        == self_dest_addr_bytes
                        && remote_ip_dgram.dest_ip.addr_bytes() == self_src_addr_bytes
                        && remote_udp_seg.dest_port == self_src_addr_port
                        && remote_udp_seg.src_port == self_dest_addr_port;

                    let is_reply = dns_reply.id() == dns_query.id();

                    if is_reply & is_from_remote {
                        for answer in dns_reply.payload.answer {
                            res.extend_from_slice(&answer.get_record_data());
                            return Ok(res);
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    Ok(res)
}

fn send_udp(
    socket_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    conn: ConnectionEndpoints,
    payload: Vec<u8>,
) -> Result<(), UdpError> {
    match conn {
        ConnectionEndpoints::V4(src, dest) => {
            let src_generic = SockAddr::V4(src.clone());
            let dest_generic = SockAddr::V4(dest.clone());

            let seg = udp::Segment::new(src_generic.clone(), dest_generic.clone(), payload)
                .map_err(|_| UdpError::Placeholder)?
                .checksum_ipv4(&src.addr(), &dest.addr(), udp::CODEPOINT)
                .map_err(|_| UdpError::Placeholder)?;

            let ip_datagram = ipv4::Datagram::<udp::Segment>::new(
                src.addr().clone(),
                dest.addr().clone(),
                seg.clone(),
            )
            .map_err(|_| UdpError::Placeholder)?
            .checksum()
            .map_err(|_| UdpError::Placeholder)?;

            let frame = ethernet::Frame::<ipv4::Datagram<udp::Segment>>::new(
                dest_mac,
                src_mac,
                ip_datagram.clone(),
            );

            let frame_as_bytes: Vec<u8> =
                Vec::try_from(&frame).map_err(|_| UdpError::Placeholder)?;

            let bytes_sent = unsafe {
                send(
                    socket_fd,
                    frame_as_bytes.as_ptr() as *const _,
                    frame_as_bytes.len(),
                    0,
                )
            };

            if bytes_sent < 0 {
                return Err(UdpError::Placeholder);
            }
        }
        ConnectionEndpoints::V6(_src, _dest) => {}
    }

    Ok(())
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

fn get_conn_4_tuple(
    dest_sock_addr: SockAddr,
    src_port: Option<u16>,
    is_tcp: bool,
) -> Result<(ConnectionEndpoints, ItfAddrs, PortGuard), ConnectionError> {
    // Create socket and bind to active interface
    let target_itf = os::get_active_wifi_interface()
        .unwrap()
        .first()
        .unwrap()
        .to_owned();

    // Get both IP addresses for target interface
    let itf_addrs = os::get_itf_addrs(&target_itf).map_err(|_| ConnectionError::GetSourceIp)?;

    // Use the same IP family as the dest address for the local address
    match dest_sock_addr {
        SockAddr::V4(_) => {
            let addr = itf_addrs.get_ipv4().ok_or(ConnectionError::GetSourceIp)?;

            let ipv4_addr =
                IPv4Address::try_from(addr.as_slice()).map_err(|_| ConnectionError::GetSourceIp)?;

            let port = src_port.unwrap_or(0);
            let src_port_guard =
                PortGuard::new(port, is_tcp).map_err(|_| ConnectionError::GetSourcePort)?;

            let src_sock_addr = SockAddrV4(ipv4_addr, src_port_guard.port);

            let endp = ConnectionEndpoints::V4(
                src_sock_addr,
                SockAddrV4::try_from(&dest_sock_addr)
                    .map_err(|_| ConnectionError::EndpointAddrFamilyMismatch)?,
            );

            Ok((endp, itf_addrs, src_port_guard))
        }
        // TODO
        SockAddr::V6(_sock_addr) => {
            let addr = itf_addrs.get_ipv6();
            if addr == None {
                return Err(ConnectionError::GetSourceIp);
            }

            let dummy_addr = IPv6Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let dummy_port_guard =
                PortGuard::new(0x0000, is_tcp).map_err(|_| ConnectionError::GetSourcePort)?;
            let dummy_sock_addr = SockAddrV6(dummy_addr, 0x0000);

            Ok((
                ConnectionEndpoints::V6(dummy_sock_addr.clone(), dummy_sock_addr),
                itf_addrs,
                dummy_port_guard
            ))

            // let ipv6_addr = IPv6Address::try_from(addr.unwrap().as_slice())
            //     .map_err(|_| TcpError::GetSourceIp)?;
            //
            // let dest_mac = compute_dest_mac_ipv6(sock_fd, src_mac, ipv6_addr, sock_addr.addr())
            //     .map_err(|_| TcpError::GetDestMac)?;
        }
    }
}

fn compute_dest_mac_ipv4(
    sock_fd: i32,
    src_mac: MacAddress,
    // This function cannot receive a ConnectionEndpoints type because a CE is only created after
    // all 4-tuple properties are computed, including the destination MAC
    src_ip: IPv4Address,
    dest_ip: IPv4Address,
) -> Result<MacAddress, ConnectionError> {
    // TODO: Figure out if it's LAN addr
    let is_lan = false;

    if is_lan {
        // If LAN -> ARP for remote IP and use remote MAC
        let dest_mac_bytes = run_arp(sock_fd, src_mac, src_ip, dest_ip).unwrap();

        return Ok(MacAddress::try_from(dest_mac_bytes.as_slice())
            .map_err(|_| ConnectionError::ArpFailed)?);
    } else {
        // If not LAN -> ARP for default gateway IP and use gateway MAC
        let gateway_ip_res = os::get_default_gateway_ipv4_addr();

        match gateway_ip_res {
            Ok(res) => match res {
                Some(ip_bytes) => {
                    let gateway_ip = IPv4Address::try_from(ip_bytes.as_slice())
                        .map_err(|_| ConnectionError::GetGatewayIp)?;

                    let dest_mac_bytes = run_arp(sock_fd, src_mac, src_ip, gateway_ip).unwrap();

                    return Ok(MacAddress::try_from(dest_mac_bytes.as_slice())
                        .map_err(|_| ConnectionError::ArpFailed)?);
                }
                // TODO: Review
                None => return Err(ConnectionError::GetGatewayIp),
            },
            Err(_) => return Err(ConnectionError::GetGatewayIp),
        }
    }
}

fn compute_dest_mac_ipv6(
    _sock_fd: i32,
    _src_mac: MacAddress,
    _src_ip: IPv6Address,
    _dest_ip: IPv6Address,
) -> Result<MacAddress, TcpError> {
    // TODO: Implement Neighbour Discovery Protocol
    Ok(MacAddress::ZERO)
}
