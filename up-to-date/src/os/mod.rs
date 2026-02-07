use libc;
use std;

pub fn drop_root_privilege() {
    unsafe {
        // Drop supplimentary groups
        libc::setgroups(0, std::ptr::null()); 
        // Drop root group id
        libc::setresgid(1000, 1000, 1000);
        // Drop root user id
        libc::setresuid(1000, 1000, 1000);
    }
}
