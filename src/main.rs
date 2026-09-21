mod crypto;
mod net;
mod os;

fn main() {
    let dest_addr = "45.33.32.156:80";
    let new_conn = net::TcpConnection::new(dest_addr).unwrap();
    // os::drop_root_privilege();
}
