pub mod com;
pub mod socket;

use std::time::{Duration, Instant};

use libc::{c_void, recv, send};

use crate::net::com::{
    address::{HardwareAddress, IPv4Address, MacAddress, ProtocolAddress},
    arp,
    ethernet::Frame,
};

use crate::net::com::{ethernet, ipv4, tcp};
// use crate::net::com::{address, arp, ethernet, ipv4, run_arp, tcp};
use crate::os;

// Port 65000 by default
// TODO: Configurable
const SRC_PORT: u16 = 0xFDE8;
const TIME_WAIT: Duration = Duration::from_secs(60);

pub struct TcpConnection {
    sock_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    src_ip: IPv4Address,
    src_port: u16,
    dest_ip: IPv4Address,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
    state: TcpState,
    time_wait_deadline: Option<std::time::Instant>,
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
    InvalidPort,
    InvalidAddress,
    MalformedAddressString,
    GetSourceIp,
    GetSourceMac,
    GetGatewayIp,
    ArpFailed,
    Handshake,
    UnclosedConnection,
    CloseConnectionFailed,
    Placeholder,
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
        let dest_port_digits: Vec<u32> = slices[1]
            .chars()
            .map(|c| c.to_digit(radix))
            .collect::<Option<Vec<u32>>>()
            .ok_or(TcpError::InvalidPort)?;

        let mut dest_port = 0;
        for d in dest_port_digits {
            dest_port = (dest_port as u16) * 10 + (d as u16);
        }

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
            let dest_mac_bytes = run_arp(sock_fd, src_mac, src_ip, dest_ip).unwrap();
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

                        let dest_mac_bytes = run_arp(sock_fd, src_mac, src_ip, gateway_ip).unwrap();

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

        let mut conn = Self {
            src_mac: src_mac,
            dest_mac: dest_mac,
            sock_fd: sock_fd,
            src_ip: src_ip,
            src_port: SRC_PORT,
            dest_ip: dest_ip,
            dest_port: dest_port,
            seq_num: 0,
            ack_num: 0,
            state: TcpState::Closed,
            time_wait_deadline: None,
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

    pub fn close(mut self) -> Result<(), TcpError> {
        let fin_res = send_fin(
            self.sock_fd,
            self.src_mac,
            self.dest_mac,
            self.src_ip,
            self.dest_ip,
            self.src_port,
            self.dest_port,
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

                                let is_from_remote = remote_ip_dgram.src_ip == self.dest_ip
                                    && remote_ip_dgram.dest_ip == self.src_ip
                                    && remote_tcp_seg.dest_port == self.src_port
                                    && remote_tcp_seg.src_port == self.dest_port;

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
                                            self.src_ip,
                                            self.dest_ip,
                                            self.src_port,
                                            self.dest_port,
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
            self.src_ip,
            self.dest_ip,
            self.src_port,
            self.dest_port,
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
                ipv4::CODEPOINT => match next_proto_cp {
                    tcp::CODEPOINT => {
                        let frame = ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::try_from(
                            &buffer[..frame_size as usize],
                        )
                        .map_err(|_| TcpError::Handshake)?;

                        let remote_ip_dgram: &ipv4::Datagram<tcp::Segment> = &frame.payload;
                        let remote_tcp_seg: &tcp::Segment = &remote_ip_dgram.payload;

                        let is_syn_from_remote = remote_ip_dgram.src_ip == self.dest_ip
                            && remote_ip_dgram.dest_ip == self.src_ip
                            && remote_tcp_seg.dest_port == self.src_port
                            && remote_tcp_seg.src_port == self.dest_port
                            && remote_tcp_seg.flags.contains(tcp::Flags::SYN);

                        let is_ack_to_syn = remote_tcp_seg.ack_num == self.seq_num;

                        if is_syn_from_remote {
                            println!("Is SYN from remote");
                            println!("Remote ACK num: {}", remote_tcp_seg.ack_num);
                            println!("Local SEQ num: {}", self.seq_num);
                            if is_ack_to_syn == false {
                                return Err(TcpError::UnclosedConnection);
                            }
                            println!("Is ACK to SYN");

                            // A SYN can't carry any payload so, unlike sending an ACK to a FIN, here we
                            // only add 1 to the remote's seq_num and don't assume any payload length
                            let new_ack = remote_tcp_seg.seq_num.wrapping_add(1);

                            self.ack_num = new_ack;

                            let ack_res = send_ack(
                                self.sock_fd,
                                self.src_mac,
                                self.dest_mac,
                                self.src_ip,
                                self.dest_ip,
                                self.src_port,
                                self.dest_port,
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

// Sets the socket timeout to the poin in time where the TCP Connection transitions from TimeWait to
// Closed
fn set_tcp_sock_timeout(sock_fd: i32, time_wait_remaining: Duration) -> Result<(), std::io::Error> {
    // According to the manC page for socket, a timeout value of zero means no timeout at all, so we
    // need to guarantee at least 1 microsecond of timeout, in case time_wait_remaining is 0 on a given call
    //
    // This is relevant because (apparently) Instant has nanosecond resolution in Linux so
    // subsec_micros() could return 0 even if there are still x nanoseconds before the deadline is reached
    // (where obviously as_secs() will also return 0)
    let time_before_timeout = time_wait_remaining.max(Duration::from_micros(1));

    let time_val = libc::timeval {
        // as _ means it is up to the compiler to infer the correct type
        tv_sec: time_before_timeout.as_secs() as _,
        tv_usec: time_before_timeout.subsec_micros() as _,
    };

    let res = unsafe {
        libc::setsockopt(
            sock_fd,
            // This option is to be applied at the socket level
            libc::SOL_SOCKET,
            // The option name. In this case, we're setting a receive timeout, which tells calls to
            // recv on this socket (for example) how long they can hang (no new frames in the socket
            // queue) until it returns an error, giving back control to the caller
            libc::SO_RCVTIMEO,
            &time_val as *const _ as *const _,
            std::mem::size_of::<libc::timeval>() as u32,
        )
    };

    if res < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn send_ack(
    socket_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    src_ip: IPv4Address,
    dest_ip: IPv4Address,
    src_port: u16,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
) -> Result<(), TcpError> {
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
    .checksum(src_ip, dest_ip, tcp::CODEPOINT)
    .map_err(|_| TcpError::Placeholder)?;

    let dat = ipv4::Datagram::<tcp::Segment>::new(src_ip, dest_ip, seg.clone())
        .map_err(|_| TcpError::Placeholder)?
        .checksum()
        .map_err(|_| TcpError::Placeholder)?;

    let frame = ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::new(dest_mac, src_mac, dat);

    let resp_frame_as_bytes: Vec<u8> = Vec::try_from(&frame).map_err(|_| TcpError::Placeholder)?;

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

fn send_fin(
    socket_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    src_ip: IPv4Address,
    dest_ip: IPv4Address,
    src_port: u16,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
) -> Result<(), TcpError> {
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
    .checksum(src_ip, dest_ip, tcp::CODEPOINT)
    .map_err(|_| TcpError::CloseConnectionFailed)?;

    let dgram = ipv4::Datagram::<tcp::Segment>::new(src_ip, dest_ip, seg.clone())
        .map_err(|_| TcpError::CloseConnectionFailed)?
        .checksum()
        .map_err(|_| TcpError::CloseConnectionFailed)?;

    let frame = ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::new(dest_mac, src_mac, dgram);

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

fn send_syn(
    socket_fd: i32,
    src_mac: MacAddress,
    dest_mac: MacAddress,
    src_ip: IPv4Address,
    dest_ip: IPv4Address,
    src_port: u16,
    dest_port: u16,
) -> Result<u32, TcpError> {
    let seg = tcp::Segment::new(
        src_ip,
        src_port,
        dest_ip,
        dest_port,
        tcp::Flags::SYN,
        vec![],
    )
    .map_err(|_| TcpError::Handshake)?
    .checksum(src_ip, dest_ip, tcp::CODEPOINT)
    .map_err(|_| TcpError::Handshake)?;

    let ip_datagram = ipv4::Datagram::<tcp::Segment>::new(src_ip, dest_ip, seg.clone())
        .map_err(|_| TcpError::Handshake)?
        .checksum()
        .map_err(|_| TcpError::Handshake)?;

    let frame =
        ethernet::Frame::<ipv4::Datagram<tcp::Segment>>::new(dest_mac, src_mac, ip_datagram);

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

// TODO:
// Actually work on error handling

pub fn tcp_incoming_handler(segment: tcp::Segment) {

    // Drop malformed segments or segments without ACK

    // Handle incoming FIN

    // Handle incoming RST
    // Handle incoming SYN
    // Handle incoming others
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

pub fn run_arp(
    socket_fd: i32,
    src_mac: MacAddress,
    src_ip: IPv4Address,
    dest_ip: IPv4Address,
) -> Option<[u8; 6]> {
    // TODO: Error handling
    let arp_datagram = arp::Datagram::new(
        HardwareAddress::MAC(src_mac),
        HardwareAddress::MAC(MacAddress::all_zero()),
        ProtocolAddress::IPv4(src_ip),
        ProtocolAddress::IPv4(dest_ip),
        arp::Operation::REQUEST,
    );

    let outbound_frame =
        Frame::<arp::Datagram>::new(MacAddress::broadcast(), src_mac, arp_datagram);

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
