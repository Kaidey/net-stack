use super::Hasher;

// Generic that tells generate() to accept any callable that implements the trait Hasher
pub fn generate<H: Hasher>(key: &[u8], message: &[u8]) -> H::Digest{

    // 1) Compute block sized key
    let block_size = H::BLOCK_SIZE;

    let mut key_block = vec![0 as u8; block_size];

    if key.len() > block_size{
        let key_digest = H::hash(key);
        let digest_vec: Vec<u8> = key_digest.into();
        key_block[..digest_vec.len()].copy_from_slice(&digest_vec);
    }else{
        key_block[..key.len()].copy_from_slice(&key);
    }

    // 2) Derive inner and outter key from block sized key
    let ipad: Vec<u8> = key_block.iter().map(|byte| byte ^ 0x36).collect();
    let opad: Vec<u8> = key_block.iter().map(|byte| byte ^ 0x5c).collect();

    // 3) Generate MAC (Message Authentication Code)
    let mut inner_input = ipad;
    inner_input.extend_from_slice(message);
    let inner_digest = H::hash(&inner_input);
    let inner_digest_vec: Vec<u8> = inner_digest.into();

    let mut outer_input = opad;
    outer_input.extend_from_slice(&inner_digest_vec);
    H::hash(&outer_input)
}
