mod net;
mod os;
mod crypto;

fn main() {
    net::test();
    os::drop_root_privilege();
}
