use crate::crypto::HashDigest;

use super::Hasher;
use core::fmt;
use std::f64;

pub struct Sha256;
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Sha256Digest([u8; 32]);

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl HashDigest for Sha256Digest{
    type Primitive = u32;
}

impl From<Sha256Digest> for Vec<u8> {
    fn from(digest: Sha256Digest) -> Self {
        digest.0.to_vec()
    }
}

impl From<Sha256Digest> for u32 {
    fn from(digest: Sha256Digest) -> Self {
        u32::from_be_bytes([digest.0[0], digest.0[1], digest.0[2], digest.0[3]])
    }
}

impl Hasher for Sha256 {
    type Digest = Sha256Digest;
    const BLOCK_SIZE: usize = 64;

    fn hash(message: &[u8]) -> Self::Digest {
        sha256(message)
    }
}

fn sha256(message: &[u8]) -> Sha256Digest {
    // 1) Create padded message block, which needs a total amount of bits divisible by 512 or a
    //    total amount of bytes divisible by 64 in this implementation

    let msg_len_bits = message.len() * 8;

    // Fixed byte with msb set to '1' + 8 bytes for 64-bit representation of message length in bits
    let pre_padding_len = message.len() + 1 + 8;

    let chunk_count;

    // The amount of chunks required determines the size of the padded message block
    if pre_padding_len % 64 == 0 {
        chunk_count = pre_padding_len / 64;
    } else {
        chunk_count = pre_padding_len / 64 + 1;
    }

    let mut padding = (64 * chunk_count) - pre_padding_len;

    let mut msg_block: Vec<u8> = Vec::new();

    // Add the message to the message block
    msg_block.extend_from_slice(&message);
    // Add fixed byte
    msg_block.push(0x80);
    // Add padding
    while padding > 0 {
        msg_block.push(0x00);
        padding -= 1;
    }
    // Add message length
    msg_block.extend_from_slice(&((msg_len_bits as u64).to_be_bytes()));

    let mut hash_values: [u32; 8] = first_n_primes(8)
        .into_iter()
        .map(|p| init_hash_value(p as f64))
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap();

    let k_constants: [u32; 64] = first_n_primes(64)
        .into_iter()
        .map(|p| init_k_constant(p as f64))
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap();

    for c in 0..chunk_count {
        // 2) Copy chunk's 16 32-bit words into message schedule (64 word array) extend them into the remaining 48
        //    words
        let msg_schedule = extend(&msg_block, &c);
        // 3) Compress message schedule
        let working_vars = compress(&msg_schedule, &hash_values, &k_constants);

        // 4) Compute final hash values
        for i in 0..hash_values.len() {
            hash_values[i] = hash_values[i].wrapping_add(working_vars[i]);
        }
    }
    // 5) Convert final digest to byte array (32-bit word -> 4 bytes)
    let mut digest = [0; 32];
    for (i, word) in hash_values.iter().enumerate() {
        let first_byte = i * 4;
        let last_byte = first_byte + 4;

        digest[first_byte..last_byte].copy_from_slice(&word.to_be_bytes());
    }

    Sha256Digest(digest)
}

fn extend(msg_block: &Vec<u8>, chunk_count: &usize) -> [u32; 64] {
    // Message schedule is an array of 64 32-bit words where the first 16 will contain the
    // chunk
    let mut msg_schedule: [u32; 64] = [0x00000000; 64];
    let mut chunk: Vec<u32> = Vec::new();

    let chunk_start = chunk_count * 64;
    let chunk_end = (chunk_count + 1) * 64;

    let mut byte_counter = chunk_start;

    // Convert every 4 bytes from the message block into a 32 bit word and push it to the chunk
    while byte_counter < chunk_end {
        let word = u32::from_be_bytes([
            msg_block[byte_counter],
            msg_block[byte_counter + 1],
            msg_block[byte_counter + 2],
            msg_block[byte_counter + 3],
        ]);
        chunk.push(word);
        byte_counter += 4;
    }

    // Insert the chunk at the begining of the message schedule
    msg_schedule[0..16].copy_from_slice(&chunk);

    // Perform Message Schedule expansion
    for i in 16..64 {
        // For i = 16 and wi being word of index i
        // sigma_0 = w1 rightrotate 7 XOR w1 rightrotate 18 XOR w1 rightshift 3
        let sigma_0 = msg_schedule[i - 15].rotate_right(7)
            ^ msg_schedule[i - 15].rotate_right(18)
            ^ msg_schedule[i - 15] >> 3;
        // sigma_1 = w14 rightrotate 17 XOR w14 rightrotate 19 XOR w14 rightshift 10
        let sigma_1 = msg_schedule[i - 2].rotate_right(17)
            ^ msg_schedule[i - 2].rotate_right(19)
            ^ msg_schedule[i - 2] >> 10;

        // Wrapping_add is addition modulo which subtracts u32::MAX - 1 from the true sum. This
        // is required because the operation below might result in a number higher than
        // u32::MAX whil results in overflow and it's the intended way to perform the addition according to the SHA-256
        // spec
        //
        // If u32::MAX = 10
        // 8+7 = 15
        // 15 - (10 + 1) = 4 -> result of 8+7 with addition modulo
        msg_schedule[i] = msg_schedule[i - 16]
            .wrapping_add(sigma_0)
            .wrapping_add(msg_schedule[i - 7])
            .wrapping_add(sigma_1);
    }
    msg_schedule
}

fn compress(msg_schedule: &[u32; 64], hash_values: &[u32; 8], k_constants: &[u32; 64]) -> [u32; 8] {
    // Calc first 8 primes -> get iterator for resulting Vec -> run init_hash_value with each
    // iter element -> collect results into Vec -> try to cast to u32 array

    let mut working_vars: [u32; 8] = [
        hash_values[0],
        hash_values[1],
        hash_values[2],
        hash_values[3],
        hash_values[4],
        hash_values[5],
        hash_values[6],
        hash_values[7],
    ];

    for i in 0..msg_schedule.len() {
        // (a and b) xor (a and c) xor (b and c)
        let majority = (working_vars[0] & working_vars[1])
            ^ (working_vars[0] & working_vars[2])
            ^ (working_vars[1] & working_vars[2]);

        // (e and f) xor ((not e) and g)
        let choice = (working_vars[4] & working_vars[5]) ^ (!working_vars[4] & working_vars[6]);

        // (a rightrotate 6) xor (a rightrotate 11) xor (a rightrotate 25)
        let epsilon_0 = working_vars[0].rotate_right(2)
            ^ working_vars[0].rotate_right(13)
            ^ working_vars[0].rotate_right(22);

        // (e rightrotate 2) xor (e righrotate 13) xor (e rightrotate 22)
        let epsilon_1 = working_vars[4].rotate_right(6)
            ^ working_vars[4].rotate_right(11)
            ^ working_vars[4].rotate_right(25);

        let temp1 = working_vars[7]
            .wrapping_add(epsilon_1)
            .wrapping_add(choice)
            .wrapping_add(k_constants[i])
            .wrapping_add(msg_schedule[i]);

        let temp2 = epsilon_0.wrapping_add(majority);

        working_vars[7] = working_vars[6];
        working_vars[6] = working_vars[5];
        working_vars[5] = working_vars[4];
        working_vars[4] = working_vars[3].wrapping_add(temp1);
        working_vars[3] = working_vars[2];
        working_vars[2] = working_vars[1];
        working_vars[1] = working_vars[0];
        working_vars[0] = temp1.wrapping_add(temp2);
    }

    working_vars
}

fn first_n_primes(number_of_primes: usize) -> Vec<u64> {
    let mut primes = Vec::with_capacity(number_of_primes);
    let mut candidate = 2;

    while primes.len() < number_of_primes {
        // all() takes a closure that returns true/false and applies it to all elements. If all
        // resolve to true, all() returns true. Else it returns false.
        // Effectively, if candidate is divisible by any of the existing primes, it is not a prime
        if primes.iter().all(|&p| candidate % p != 0) {
            primes.push(candidate);
        }
        candidate += 1;
    }

    primes
}

fn init_hash_value(prime_number: f64) -> u32 {
    let sqrt = prime_number.sqrt();

    let fractional = sqrt.fract();

    // u64 -> integer
    // 1 to the power of 32 is the same as a bitwise left-shift by 32 bits
    // Every 1-bit shift moves the '1' bit one place, doubling the decimal value, which is the same
    // as a power
    //
    // Here we multiply the fraction by 2^32 to extract the first 32 bits of its binary
    // representation. This has to be done this way because of the way floats are stored in binary.
    // (Look up mantissa, exponent, sign)
    let hash = (fractional * (1u64 << 32) as f64) as u32;

    hash
}

fn init_k_constant(prime_number: f64) -> u32 {
    let cbrt = prime_number.cbrt();

    let fractional = cbrt.fract();

    let k = (fractional * (1u64 << 32) as f64) as u32;

    k
}
