//! A 32-byte key used for AES-256 encryption and decryption.
use std::ops::Deref;

/// A 32-byte key used for AES-256 encryption and decryption.
pub struct Aes256Key {
    bytes: [u8; 32],
}
impl Aes256Key {}
impl Deref for Aes256Key {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}
