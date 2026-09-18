use libc;
use std::{
    fs,
    io::{self, Read},
    ptr,
};

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

pub fn get_itf_mac_address(target_itf_name: &str) -> Result<Option<String>, io::Error> {
    let current_os = std::env::consts::OS;

    // TODO: Windows
    if current_os == "linux" {
        let net_dir = std::path::Path::new("/sys/class/net");
        let dir_content_iter =
            fs::read_dir(net_dir).or_else(|_| Err(io::Error::last_os_error()))?;

        // Each interface will have their own sys/class/net/<itf_name>
        let itf_dirs: Vec<String> = dir_content_iter
            .filter_map(|ent_res| ent_res.ok())
            .map(|ent| ent.file_name().into_string().unwrap())
            .collect::<Vec<String>>();

        for dir in itf_dirs {
            if dir == target_itf_name {
                // Inside each itf's dir, there is a file "address" that contains its MAC
                let full_path = net_dir.join(dir).join("address");
                let mut file: fs::File =
                    fs::File::open(full_path).or_else(|_| Err(io::Error::last_os_error()))?;
                let mut mac_addr_str = String::new();

                file.read_to_string(&mut mac_addr_str)
                    .or_else(|_| Err(io::Error::last_os_error()))?;
                return Ok(Some(mac_addr_str));
            }
        }
    }
    Ok(None)
}

pub fn get_itf_ipv4_address(target_itf_name: &str) -> Result<Option<[u8; 4]>, io::Error> {
    let current_os = std::env::consts::OS;

    // TODO: Windows
    if current_os == "linux" {
        unsafe {
            // Init null pointer
            let mut itf_addr_ll = ptr::null_mut();
            // Now points to Linked List that holds all interface addresses
            let res = libc::getifaddrs(&mut itf_addr_ll);

            if res == 0 {
                // Start with first element of LL
                let mut next_addr_ptr: *mut libc::ifaddrs = itf_addr_ll;
                while next_addr_ptr.is_null() == false {
                    let next_addr: libc::ifaddrs = *next_addr_ptr;
                    let addr_family = (*next_addr.ifa_addr).sa_family;

                    let itf_name = std::ffi::CStr::from_ptr(next_addr.ifa_name).to_string_lossy();

                    if target_itf_name == itf_name {
                        match addr_family as _ {
                            // IPv4 family
                            libc::AF_INET => {
                                let ip_sockaddr_ptr = next_addr.ifa_addr as *mut libc::sockaddr_in;
                                // to_ne_bytes() is used here because s_addr is already stored in
                                // network byte order. Meaning the most significant byte of the
                                // address is stored as the msb of the in-memory byte sequence
                                let addr_bytes = (*ip_sockaddr_ptr).sin_addr.s_addr.to_ne_bytes();
                                return Ok(Some(addr_bytes));
                            }
                            _ => {}
                        }
                    }
                    next_addr_ptr = next_addr.ifa_next;
                }
                // Free the memory allocated for the LL
                libc::freeifaddrs(itf_addr_ll);
            } else {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(None)
}
