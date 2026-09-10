pub fn byte_alignment_padding(
    header_len: usize,
    alignment: usize,
    padding_vec: &mut Vec<u8>,
) -> usize {
    let mut header_len_cpy = header_len.clone();

    while header_len_cpy % alignment != 0 {
        padding_vec.push(0);
        header_len_cpy = header_len_cpy + 1;
    }

    header_len_cpy
}

pub fn fixed_size_header_padding(header_len: usize, target_len: usize, padding_vec: &mut Vec<u8>) {
    let mut header_len_cpy = header_len.clone();

    while header_len_cpy < target_len {
        padding_vec.push(0);
        header_len_cpy = header_len_cpy + 1;
    }
}

pub fn calc_checksum(byte_array: &[u8]) -> u16 {
    let mut count = 0;
    let mut sum: u32 = 0;

    // Calculate sum of every 16 bit word on the datagram header
    while count < byte_array.len() {
        // Combine 2 bytes into a 16 bit word
        let next_16bit_word = ((byte_array[count] as u16) << 8) | byte_array[count + 1] as u16;

        sum = sum + next_16bit_word as u32;
        count = count + 2;
    }

    // Checksum needs to be a 16 bit word, so, if the final sum is more than 16 bits, we
    // remove the extra bits (most significant) and add them onto the checksum word (16
    // least significant bits)

    // 16-bit right shift to extract extra bits
    //
    // E.g: sum = 2D130 -> extra_bits = 2
    let extra_bits = sum >> 16;

    // 16-bit left shift to discard most significant extra bits followed by 16-bit right shift
    // to restore the original least significant 16-bit word
    //
    // E.g: sum = 2D130 -> sum_ls16bit = D130
    let sum_ls16bit = (sum << 16) >> 16;

    // Add the extra bits to the least significant 16 bits of the final sum
    // and calculate the 1's complement of the resulting value (flipping all bits) using XOR
    ((sum_ls16bit + extra_bits) ^ 0xFFFF)
        .try_into()
        .expect("Checksum is greater than 16 bits")
}
