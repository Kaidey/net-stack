use std::sync::LazyLock;

pub mod hmac;
pub mod sha_256;

pub trait Hasher {
    type Digest: Into<Vec<u8>>;
    const BLOCK_SIZE: usize;

    fn hash(message: &[u8]) -> Self::Digest;
}

pub struct CryptoSecret([u8; 32]);

impl CryptoSecret {
    pub fn new() -> Self {
        let mut secret = [0; 32];

        getrandom::fill(&mut secret).expect("[Secret Creation] Failed to get random bytes");

        CryptoSecret(secret)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub static SECRET: LazyLock<CryptoSecret> = LazyLock::new(CryptoSecret::new);
