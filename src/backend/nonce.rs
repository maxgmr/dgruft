//! 12-byte nonce used to encrypt bytes according to the Aes-256 method.
use std::ops::Deref;

/// 12-byte nonce used to encrypt bytes according to the Aes-256 method.
pub struct Nonce {
    bytes: [u8; 12],
}
impl Nonce {}
impl Deref for Nonce {
    type Target = [u8; 12];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}
