struct EthernetFrame {
    // Alternating 1's and 0's for destination clock synchronization
    preamble: Vec<u8>,
    // Marks start of frame
    start_frame_delimiter: Vec<u8>,
    dest_mac_address: Vec<u8>,
    source_mac_address: Vec<u8>,
    // Type or length of the payload
    type_or_length: Vec<u8>,
    data: Vec<u8>,
    frame_check_sequence: Vec<u8>,
}

impl EthernetFrame {
    pub fn new(
        dest_mac_address: Vec<u8>,
        source_mac_address: Vec<u8>,
        type_or_length: Vec<u8>,
        data: Vec<u8>,
    ) -> Self {
        // Calculate checksum for frame_check_sequence using the CRC-32 algorithm
        let checksum = Vec::from([1, 1]);
        Self {
            preamble: Vec::from([1, 0, 1, 0, 1, 0, 1]),
            start_frame_delimiter: Vec::from([1, 0, 1, 0, 1, 0, 1, 1]),
            dest_mac_address: dest_mac_address,
            source_mac_address: source_mac_address,
            type_or_length: type_or_length,
            data: data,
            frame_check_sequence: checksum,
        }
    }
}

// Find Default Gateway IP
// ARP request to find MAC of said IP
