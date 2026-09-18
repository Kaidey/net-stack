use crate::net::test_parsing;

mod crypto;
mod net;

fn main() {
    let dest_addr = "192.168.68.1:80";
    let new_conn = net::TcpConnection::new(dest_addr);
    // test_parsing(dest_addr);
    // os::drop_root_privilege();
}
