mod com;
mod socket;

use com::{ArpAddressTypes, ArpPacket, EthernetFrame};
use libc::{c_void, recv};

use crate::net::com::FrameType;

pub fn test() {
    let arp_packet = ArpPacket::new_arp_request_packet(
        ArpAddressTypes::ETHERNET,
        ArpAddressTypes::IPV4,
        [0, 0, 0, 0, 0, 1],
        [0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0],
    );

    let eth_frame = EthernetFrame::new(
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        [0, 0, 0, 0, 0, 0],
        FrameType::ARP,
        arp_packet.to_bytes(),
    );


    // Since new_socket() is a generic, we need to tell the compiler what type None should be
    // treated as. The function expects any type that implements Into<String>, so we tell the comp
    // to treat None as a String

    // let sock_fd = socket::new_socket(None::<String>);
    //
    // let mut buffer = [0u8; 65536];
    //
    // println!("Listening for packets");
    // loop {
    //     let packet_size =
    //         unsafe { recv(sock_fd, buffer.as_mut_ptr() as *mut c_void, buffer.len(), 0) };
    //
    //     if packet_size < 0 {
    //         panic!(
    //             "Error receiving packet: {}",
    //             std::io::Error::last_os_error()
    //         );
    //     }
    //
    //     let packet: Vec<u8> = buffer[..packet_size as usize].to_vec();
    //
    //     println!("Received packet: {:02X?}", packet);
    // }
}
