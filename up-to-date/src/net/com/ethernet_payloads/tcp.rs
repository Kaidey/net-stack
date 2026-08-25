use crate::net::com::ethernet_payloads::utils;
use core::fmt;

pub struct Segment {
    src_port: u16,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
    // In the struct, header length will be used as the total byte count instead of the 32-bit word
    // count for simplicity. Convertion will happen when transforming a struct instance into a byte
    // stream and when creating an instance from a byte stream
    hlen: u8,
    flags: TcpFlags,
    window: u16,
    checksum: u16,
    urgent_ptr: u16,
    opts: Vec<u8>,
    payload: Vec<u8>,
}

#[derive(Clone, Copy)]
#[repr(u16)]
// TODO: Remake this. A TCP header can have multiple flags enabled
pub enum TcpFlags {
    None = 0,
    FIN = 1,
    SYN = 2,
    RST = 4,
    PSH = 8,
    ACK = 16,
    URG = 32,
    ECE = 64,
    CWR = 128,
    AE = 256,
}

impl TcpFlags {
    // TODO: Swap to impl Display
    pub fn to_string(self) -> &'static str {
        match self {
            TcpFlags::None => "No Flags",
            TcpFlags::FIN => "Finish",
            TcpFlags::SYN => "Synchronize",
            TcpFlags::RST => "Reset Connection",
            TcpFlags::PSH => "Push",
            TcpFlags::ACK => "Acknowledge",
            TcpFlags::URG => "Urgent",
            TcpFlags::ECE => "ECN Echo",
            TcpFlags::CWR => "Congestion Window Reduced",
            TcpFlags::AE => "Accurate ECN",
        }
    }
}

// TODO: Change after remake of flags
impl From<u16> for TcpFlags {
    fn from(flags: u16) -> Self {
        match flags {
            flags if flags == TcpFlags::None as u16 => TcpFlags::None,
            flags if flags == TcpFlags::FIN as u16 => TcpFlags::FIN,
            flags if flags == TcpFlags::SYN as u16 => TcpFlags::SYN,
            flags if flags == TcpFlags::RST as u16 => TcpFlags::RST,
            flags if flags == TcpFlags::PSH as u16 => TcpFlags::PSH,
            flags if flags == TcpFlags::ACK as u16 => TcpFlags::ACK,
            flags if flags == TcpFlags::URG as u16 => TcpFlags::URG,
            flags if flags == TcpFlags::ECE as u16 => TcpFlags::ECE,
            flags if flags == TcpFlags::CWR as u16 => TcpFlags::CWR,
            flags if flags == TcpFlags::AE as u16 => TcpFlags::AE,
            _ => panic!("Unknown flag"),
        }
    }
}

impl Segment {
    pub fn new(src_port: u16, dest_port: u16, flags: TcpFlags, payload: Vec<u8>) -> Self {
        let default_hlen = 20;

        let mut segment: Self = Self {
            src_port: src_port,
            dest_port: dest_port,
            seq_num: Self::gen_seq_num(),
            ack_num: 0,
            hlen: default_hlen,
            flags: flags,
            window: 0,
            checksum: 0,
            urgent_ptr: 0,
            opts: vec![],
            payload: payload,
        };

        segment.checksum = utils::calc_checksum(&segment.to_bytes());

        segment
    }

    pub fn ack(mut self, ack_num: u32) -> Self {
        self.ack_num = ack_num;
        self
    }

    pub fn seq(mut self, seq_num: u32) -> Self {
        self.seq_num = seq_num;
        self
    }

    pub fn opts(mut self, opts: Vec<u8>) -> Self {
        self.opts = opts;

        let post_opts_hlen = self.hlen as usize + self.opts.len();

        let post_padding_hlen = utils::byte_alignment_padding(post_opts_hlen, 4, &mut self.opts);

        if post_padding_hlen > 60 {
            panic!("[TCP][Segment][AddOpts] TCP segment header length is more than maximum 60");
        }

        self.hlen = post_padding_hlen as u8;
        utils::calc_checksum(&self.to_bytes()[0..post_padding_hlen]);
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        // Divide hlen by 4 since header length field is calculated in 32-bit words
        let hlen_and_flags: u16 = ((self.hlen / 4) as u16) << 12 | self.flags as u16;

        bytes.extend_from_slice(&self.src_port.to_be_bytes());
        bytes.extend_from_slice(&self.dest_port.to_be_bytes());
        bytes.extend_from_slice(&self.seq_num.to_be_bytes());
        bytes.extend_from_slice(&self.ack_num.to_be_bytes());
        bytes.extend_from_slice(&hlen_and_flags.to_be_bytes());
        bytes.extend_from_slice(&self.window.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.extend_from_slice(&self.urgent_ptr.to_be_bytes());
        bytes.extend_from_slice(&self.opts);
        bytes.extend_from_slice(&self.payload);

        bytes
    }

    // Generate the Initial Sequence Number
    // TODO
    fn gen_seq_num() -> u32 {
        0
    }
}
