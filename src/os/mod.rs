use libc;
use std::{
    error::Error,
    fs,
    io::{self, Read},
    ptr,
};

pub struct ItfAddrs {
    ipv4: Option<[u8; 4]>,
    ipv6: Option<[u8; 16]>,
}

impl ItfAddrs {
    pub fn new() -> Self {
        Self {
            ipv4: None,
            ipv6: None,
        }
    }

    pub fn set_ipv4(&mut self, addr: [u8; 4]) {
        self.ipv4 = Some(addr);
    }

    pub fn set_ipv6(&mut self, addr: [u8; 16]) {
        self.ipv6 = Some(addr);
    }

    pub fn get_ipv4(&self) -> Option<[u8;4]>{
        self.ipv4
    }

    pub fn get_ipv6(&self) -> Option<[u8;16]>{
        self.ipv6
    }
}

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

// TODO: Review functions below, try to make the return types consistent and addept net::address
// methods

fn itf_is_up(itf: &str) -> bool {
    fs::read_to_string(format!("/sys/class/net/{itf}/operstate"))
        .map(|st| st.trim() == "up")
        .unwrap_or(false)
}

pub fn get_active_wifi_interface() -> Result<Vec<String>, io::Error> {
    let itfs: Vec<String> = fs::read_dir("/sys/class/net")?
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|itf| itf != "lo" && itf_is_up(itf))
        .collect();

    Ok(itfs)
}

pub fn get_default_gateway_ipv4_addr() -> Result<Option<Vec<u8>>, io::Error> {
    let current_os = std::env::consts::OS;

    if current_os == "linux" {
        let routes_dir = std::path::Path::new("/proc/net/");
        let routes_file_path = routes_dir.join("route");

        let mut routes: fs::File =
            fs::File::open(routes_file_path).or_else(|_| Err(io::Error::last_os_error()))?;
        let mut file_content = String::new();
        routes
            .read_to_string(&mut file_content)
            .or_else(|_| Err(io::Error::last_os_error()))?;

        if file_content.len() == 0 {
            return Ok(None);
        }

        // IMPORTANT: The following code is tightly coupled with the structure of the file
        // /proc/net/routes and, based on that, makes several assumptions about the contents of
        // file_content

        // Remove every tab and whitespace in the file contents, replacing them with '-' so we can
        // split and get all separate char sequences in a vec
        let whitespace_replacer = "-";
        let file_content_no_ws = file_content
            .replace('\t', whitespace_replacer)
            .replace(" ", "");

        // Split file contents into separate lines
        let lines = file_content_no_ws.split("\n");

        // Will hold the column number (starting at 0) of the column that contains the char
        // sequence 'Gateway'
        let mut lookup_col_num = 0;

        for line in lines {
            // Split each line based on the char we used to replace all white space
            // This gives us a list of all contiguous char sequences
            let mut line_split = line.split(whitespace_replacer);

            // Find index of the char sequence 'Gateway' if the line contains it. This will allows
            // us to check only that index in the actual route lines, which will contain 0 or the
            // Gateway IPv4 addr
            if line.contains("Gateway") {
                let gateway_addr_column_res = line_split.position(|s| s == "Gateway");
                match gateway_addr_column_res {
                    Some(col_num) => lookup_col_num = col_num,
                    None => return Ok(None),
                }
            } else {
                if lookup_col_num != 0 {
                    // On lines beyond the first, get the value on the same column as 'Gateway'
                    let lookup_res = line_split.nth(lookup_col_num);
                    match lookup_res {
                        Some(addr_str) => {
                            if addr_str != "00000000" {
                                // Convert hex string to hex bytes 'AB12C4D8' -> [0xAB, 0x12, 0xC4,
                                // 0xD8]
                                let res: Result<Vec<u8>, io::Error> = (0..addr_str.len())
                                    .step_by(2)
                                    .map(|i| {
                                        u8::from_str_radix(&addr_str[i..i + 2], 16)
                                            .map_err(|_| io::Error::last_os_error())
                                    })
                                    .collect();
                                match res {
                                    Ok(mut bytes) => {
                                        if bytes.len() != 4 {
                                            return Ok(None);
                                        } else {
                                            // Reverse byte array, as the addresses are represented
                                            // in Little Endian on the routes file
                                            bytes.reverse();
                                            return Ok(Some(bytes));
                                        }
                                    }
                                    Err(err) => return Err(err),
                                }
                            }
                        }
                        None => {}
                    }
                }
            }
        }
    }
    Ok(None)
}

pub fn get_itf_mac_addr(target_itf_name: &str) -> Result<Option<String>, io::Error> {
    let current_os = std::env::consts::OS;

    if current_os == "linux" {
        let net_dir = std::path::Path::new("/sys/class/net");
        let dir_content_iter =
            fs::read_dir(net_dir).or_else(|_| Err(io::Error::last_os_error()))?;

        // Each interface will have their own sys/class/net/<itf_name>
        let itf_dirs: Vec<String> = dir_content_iter
            // Filters out any Result<DirEntry, Error> that evaluate to Err
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

pub fn get_itf_addrs(target_itf_name: &str) -> Result<ItfAddrs, io::Error> {
    let current_os = std::env::consts::OS;

    let mut itf_addrs = ItfAddrs::new();

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
                                // to_ne_bytes() is used here because s_addr is a u32 which we need to convert to a byte array
                                // However, the u32 is already  stored in network byte order. Meaning the most significant byte 
                                // of the address is stored as the msb of the in-memory byte sequence aka big-endian
                                let addr_bytes = (*ip_sockaddr_ptr).sin_addr.s_addr.to_ne_bytes();
                                itf_addrs.set_ipv4(addr_bytes)
                            }
                            libc::AF_INET6 => {
                                let ip_sockaddr_ptr = next_addr.ifa_addr as *mut libc::sockaddr_in6;
                                let addr_bytes = (*ip_sockaddr_ptr).sin6_addr.s6_addr;
                                itf_addrs.set_ipv6(addr_bytes)
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
    Ok(itf_addrs)
}

pub enum IpTableRuleAction {
    Insert,
    Delete,
}

// Add an IPTables rule to drop the kernel's RST-Block for unknown SYN/ACK
// Raw Sockets operate along the Kernel's own IP/TCP stack, which means it parses,
// independently, the same SYN/ACK I receive. Since it has no idea that the port I use for TCP
// connections is actually being used, it assumes the SYN/ACK is not supposed to be received by
// the port and sends an RST
pub fn switch_iptables_kernel_rst_block(
    src_port: u16,
    action: IpTableRuleAction,
) -> Result<bool, std::io::Error> {
    let flag = match action {
        IpTableRuleAction::Insert => "-I",
        IpTableRuleAction::Delete => "-D",
    };
    let port = src_port.to_string();
    let mut args = vec![flag, "OUTPUT"];

    // 1 is only used in Insert since it tells the command to insert the rule in the first position
    // of the list so it has the highest priority
    if matches!(action, IpTableRuleAction::Insert) {
        args.push("1");
    }
    args.extend([
        "-p",
        "tcp",
        "--tcp-flags",
        "RST",
        "RST",
        "--sport",
        &port,
        "-j",
        "DROP",
    ]);

    Ok(std::process::Command::new("iptables")
        .args(&args)
        .status()?
        .success())
}
