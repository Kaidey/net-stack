// Remove Later
#![allow(dead_code)]

use crate::net::com::http;

mod crypto;
mod net;
mod os;

// TODO:
// Replace pub struct properties with getter methods or analogous
// FIN retransmist for TCP Close and retransmits in genera
// IPv4 Fragmentation
// IPv4 and TCP Options
// TCP LIstener
// Handle dropping iptables rule on SIGINT. Currently only handled when TCP Connection is closed

fn main() {
    let name = "http://scanme.nmap.org";
    // let name = "http://api.agify.io?name=jose"; 

    http::Client::get(name).unwrap();

    // os::drop_root_privilege();
}
