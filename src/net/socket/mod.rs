use core::time::Duration;
use libc::*;
use std::{ffi::CString, mem::size_of, mem::zeroed};

pub fn new_socket(net_itf: &str) -> i32 {
    // Linux kernel expects protocol parameter as Big Endian i32
    let sock_fd = unsafe { socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
    if sock_fd < 0 {
        panic!(
            "Failed to create socket: {}",
            std::io::Error::last_os_error()
        );
    }

    let itf_as_cstring = CString::new(net_itf).unwrap();

    interface_bind_packet_socket(sock_fd, itf_as_cstring);

    sock_fd
}

fn interface_bind_packet_socket(sock_fd: i32, net_itf: CString) {
    // Get the index for interface with name net_itf
    let net_itf_idx = unsafe { if_nametoindex(net_itf.as_ptr()) };

    // Create an instance of a data-link layer socket address
    let mut sock_addr: sockaddr_ll = unsafe { zeroed() };
    sock_addr.sll_family = AF_PACKET as u16;
    sock_addr.sll_protocol = (ETH_P_ALL as u16).to_be();
    sock_addr.sll_ifindex = net_itf_idx as i32;

    // Creates a raw pointer (C style) to the value of sock_addr with the same type
    // PS: Rust's bind() is essentially a call to C's bind() via the Foreign Function Interface
    let sock_addr_raw_ptr = &sock_addr as *const _;

    // C's bind() function expects a sockaddr generic socket type, but here we are working with a
    // sockaddr_ll. Thus the need to cast into this generic type (which requires the previous cast
    // to a raw pointer so C understands it)
    let gen_sock_addr_raw_ptr = sock_addr_raw_ptr as *const sockaddr;

    let bind_result = unsafe {
        bind(
            sock_fd,
            gen_sock_addr_raw_ptr,
            size_of::<sockaddr_ll>() as socklen_t,
        )
    };

    if bind_result < 0 {
        panic!(
            "Failed to bind socket to interface {:?}: {}",
            net_itf,
            std::io::Error::last_os_error()
        );
    }
}

// Reserves a free ephemeral TCP port by binding to port 0 (but never listening).
// Returns the socket file descriptor and the port, because we need to manually close the socket
// after the TCP Connection ends and also because we need to keep the fd in scope in order for the
// socket to stay live. If the socket is closed, there is no guarantee that the port is still
// reserved for the process. If the process is forcibly killed no action is needed since the
// kernel closes any sockets owned by it.
pub fn reserve_tcp_port() -> (i32, u16) {
    let fd = unsafe { socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        panic!(
            "Failed to create port reservation socket: {}",
            std::io::Error::last_os_error()
        );
    }

    // With a zeroed sockaddr_in, the kernel picks the port
    let mut addr: sockaddr_in = unsafe { zeroed() };
    addr.sin_family = AF_INET as sa_family_t;

    let size = size_of::<sockaddr_in>() as socklen_t;

    let bind_result = unsafe { bind(fd, &addr as *const _ as *const sockaddr, size) };
    if bind_result < 0 {
        panic!(
            "Failed to bind reservation socket: {}",
            std::io::Error::last_os_error()
        );
    }

    // Ask the kernel which port we got
    let mut len = size;
    let name_result = unsafe { getsockname(fd, &mut addr as *mut _ as *mut sockaddr, &mut len) };
    if name_result < 0 {
        panic!(
            "Failed to read reserved port: {}",
            std::io::Error::last_os_error()
        );
    }

    (fd, u16::from_be(addr.sin_port))
}

// Sets the socket timeout to the point in time where the TCP Connection transitions from TimeWait to
// Closed
pub fn set_tcp_sock_timeout(
    sock_fd: i32,
    time_wait_remaining: Duration,
) -> Result<(), std::io::Error> {
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
