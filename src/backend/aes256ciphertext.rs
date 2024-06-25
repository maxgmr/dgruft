//! Bytes encrypted by the AES-256 method.
use std::ops::Deref;

/// Bytes encrypted by the AES-256 method.
pub struct Aes256Ciphertext {
    bytes: [u8],
}
impl Aes256Ciphertext {}
impl Deref for Aes256Ciphertext {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}
