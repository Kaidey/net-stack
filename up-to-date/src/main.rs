mod net;
mod os;

fn main() {
    net::test();
    os::drop_root_privilege();
}
