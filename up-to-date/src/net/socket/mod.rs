use libc::*;
use std::{ffi::CString, mem::size_of, mem::zeroed};

pub fn new_socket<T: Into<String>>(net_itf: Option<T>) -> i32 {
    let itf: String = match net_itf {
        Some(value) => value.into(),
        None => String::from("eth0"),
    };

    // Linux kernel expects protocol parameter as Big Endian i32
    let sock_fd = unsafe { socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
    if sock_fd < 0 {
        panic!(
            "Failed to create socket: {}",
            std::io::Error::last_os_error()
        );
    }
    println!("Socket File Descriptor >> {sock_fd}");

    println!("Binding socket to interface {itf}");
    let itf_as_cstring = CString::new(itf).unwrap();

    interface_bind_packet_socket(sock_fd, itf_as_cstring);

    sock_fd
}

fn interface_bind_packet_socket(sock_fd: i32, net_itf: CString) {
    // Get the index for interface with name net_itf
    let net_itf_idx = unsafe { if_nametoindex(net_itf.as_ptr()) };
    println!("Index for interface {:?} is {net_itf_idx}", net_itf);

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
    } else {
        println!(
            "Successfully bound socket {sock_fd} to interface {:?}",
            net_itf
        );
    }
}

// Only works with AF_INET sockets as per https://linux.die.net/man/7/socket
fn interface_bind_ipv4_socket(sock_fd: i32, net_itf: CString) {
    unsafe {
        let bind_result = setsockopt(
            sock_fd,
            // Apply option at the socket level
            SOL_SOCKET,
            // Use option to bind socket to an ethernet interface
            SO_BINDTODEVICE,
            // Value of the option is a pointer of type void (any type) to the interface's name
            net_itf.as_ptr() as *const libc::c_void,
            // Linux kernel always copies a fixed amount of bytes for the interface name which is defined in the constant IFNAMSIZ (interface name size)
            libc::IFNAMSIZ as libc::socklen_t,
        );

        if bind_result < 0 {
            panic!(
                "Failed to bind socket to interface {:?}: {}",
                net_itf,
                std::io::Error::last_os_error()
            );
        }
    }
}
