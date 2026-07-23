mod com;
mod socket;

use std::str::FromStr;

use com::{ArpAddressTypes, ArpPacket, EthernetFrame};
use libc::{c_void, recv, send};

use crate::net::com::FrameType;

pub fn test() {
    let arp_packet = ArpPacket::new_arp_request_packet(
        ArpAddressTypes::ETHERNET,
        ArpAddressTypes::IPV4,
        [0x94, 0xbb, 0x43, 0x4e, 0xce, 0xbc],
        [192, 168, 68, 101],
        [0, 0, 0, 0, 0, 0],
        [192, 168, 68, 100],
    );

    let eth_frame = EthernetFrame::new(
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        [0x94, 0xbb, 0x43, 0x4e, 0xce, 0xbc],
        FrameType::Arp.hex_value(),
        arp_packet.to_bytes(),
    );

    let sock_fd = socket::new_socket(Some("eth1"));

    let frame_as_bytes = eth_frame.to_bytes();

    println!("\nSending Ethernet Frame {}\n", EthernetFrame::from(frame_as_bytes.clone()));

    let bytes_sent = unsafe {
        send(
            sock_fd,
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
    // Since new_socket() is a generic, we need to tell the compiler what type None should be
    // treated as. The function expects any type that implements Into<String>, so we tell the comp
    // to treat None as a String

    let mut buffer = [0u8; 65536];

    println!("Listening for frames");
    loop {
        let frame_size =
            unsafe { recv(sock_fd, buffer.as_mut_ptr() as *mut c_void, buffer.len(), 0) };

        if frame_size < 0 {
            panic!(
                "Error receiving frame: {}",
                std::io::Error::last_os_error()
            );
        }

        let frame: Vec<u8> = buffer[..frame_size as usize].to_vec();

        println!("\n##### Received Ethernet frame ##### {}\n", Into::<EthernetFrame>::into(frame.clone()));
    }
}
