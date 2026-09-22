mod crypto;
mod net;
mod os;

fn main() {
    // Drop the kernel's RST-Block for unknown SYN/ACK
    // Raw Sockets operate along the Kernel's own IP/TCP stack, which means it parses,
    // independently, the same SYN/ACK I receive. Since it has no idea that the port I use for TCP
    // connections is actually being used, it assumes the SYN/ACK is not supposed to be received by
    // the port and sends an RST
    let status = std::process::Command::new("iptables")
        .args([
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "RST",
            "RST",
            "-s",
            "192.168.68.101",
            "--sport",
            "65000",
            "-j",
            "DROP",
        ])
        .status()
        .expect("failed to run iptables");
    if !status.success() {
        panic!("iptables add rule failed");
    }

    let dest_addr = "45.33.32.156:80";
    let new_conn = net::TcpConnection::new(dest_addr).unwrap();
    // os::drop_root_privilege();
}
