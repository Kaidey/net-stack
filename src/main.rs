// Remove Later
#![allow(dead_code)]

// use crate::net::{com::{address::IPv4Address, ethernet, ipv4, udp}, resolve_domain_name};

use crate::net::com::http;

mod crypto;
mod net;
mod os;

// TODO:
// Size validations for TCP, UDP Segments and Eth Frames
// Eth frame padding
// Replace pub struct properties with getter methods or analogous
// FIN retransmist for TCP Close and retransmits in genera
// IPv4 Fragmentation
// IPv4 and TCP Options
// TCP LIstener
// Handle dropping iptables rule on SIGINT. Currently only handled when TCP Connection is closed
// HTTP Client

fn main() {
    let name = "http://scanme.nmap.org";

    http::Client::get(name).unwrap();

    // os::drop_root_privilege();
}
