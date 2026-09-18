mod crypto;
mod net;
mod os;

fn main() {
    let dest_addr = "192.168.68.1:80";
    let new_conn = net::TcpConnection::new(dest_addr).unwrap();
    // os::drop_root_privilege();
}
