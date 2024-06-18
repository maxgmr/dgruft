//! Functionality related to hashing.
use pbkdf2::pbkdf2_hmac;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use sha2::Sha256;

use crate::{error::Error, helpers};

/// 32 bytes hashed and salted using PBKDF2-HMAC-SHA256 and 64-byte salt.
#[derive(Debug)]
pub struct Hashed {
    hash: [u8; 32],
    salt: [u8; 64],
}
impl Hashed {
    const NUM_ITERATIONS: u32 = 50_000;

    /// Hash and salt the given bytes.
    pub fn new(input_bytes: &[u8]) -> Self {
        let mut salt = [0u8; 64];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut salt);

        Self::from_salt(input_bytes, &salt)
    }

    /// Hash a byte array using a given salt.
    pub fn from_salt(input_bytes: &[u8], salt: &[u8; 64]) -> Self {
        let mut hash = [0u8; 32];
        pbkdf2_hmac::<Sha256>(input_bytes, salt, Self::NUM_ITERATIONS, &mut hash);

        Self { hash, salt: *salt }
    }

    /// Read a [Hashed] from a base-64 string.
    pub fn from_b64(b64_hash: &str, b64_salt: &str) -> Result<Self, Error> {
        Ok(Self {
            hash: helpers::b64_to_fixed::<&str, 32>(b64_hash, "b64_hash")?,
            salt: helpers::b64_to_fixed::<&str, 64>(b64_salt, "b64_salt")?,
        })
    }

    /// Check if the given bytes match the original bytes used to make this [Hashed].
    pub fn check_match(&self, input_bytes: &[u8]) -> bool {
        let hashed_input = Self::from_salt(input_bytes, self.salt());
        *self.hash() == *hashed_input.hash()
    }

    // GETTERS

    /// Return the hash of this [Hashed].
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Return the hash of this [Hashed] as a base-64 string.
    pub fn hash_as_b64(&self) -> String {
        helpers::bytes_to_b64(&self.hash)
    }

    /// Return the salt of this [Hashed].
    pub fn salt(&self) -> &[u8; 64] {
        &self.salt
    }

    /// Return the salt of this [Hashed] as a base-64 string.
    pub fn salt_as_b64(&self) -> String {
        helpers::bytes_to_b64(&self.salt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::{assert_eq, assert_ne};

    fn test_hash() -> &'static [u8; 32] {
        &[
            228u8, 229u8, 52u8, 90u8, 187u8, 181u8, 72u8, 158u8, 154u8, 52u8, 159u8, 127u8, 212u8,
            38u8, 45u8, 177u8, 111u8, 20u8, 254u8, 52u8, 171u8, 100u8, 79u8, 128u8, 116u8, 164u8,
            53u8, 84u8, 36u8, 101u8, 156u8, 146u8,
        ]
    }

    fn test_salt() -> &'static [u8; 64] {
        &[
            143u8, 207u8, 88u8, 34u8, 132u8, 74u8, 129u8, 80u8, 206u8, 110u8, 103u8, 116u8, 93u8,
            12u8, 237u8, 139u8, 34u8, 105u8, 169u8, 154u8, 95u8, 29u8, 201u8, 247u8, 111u8, 5u8,
            85u8, 70u8, 58u8, 19u8, 185u8, 232u8, 86u8, 244u8, 29u8, 140u8, 125u8, 90u8, 224u8,
            153u8, 19u8, 37u8, 115u8, 174u8, 57u8, 122u8, 113u8, 32u8, 208u8, 227u8, 111u8, 252u8,
            248u8, 158u8, 188u8, 40u8, 5u8, 26u8, 178u8, 176u8, 128u8, 61u8, 221u8, 106u8,
        ]
    }

    #[test]
    fn test_pbkdf() {
        let hash_1 = Hashed::new(b"password");
        let hash_2 = Hashed::new(b"password");
        assert_ne!(hash_1.hash_as_b64(), hash_2.hash_as_b64());
        assert_ne!(hash_1.hash(), hash_2.hash());

        assert!(hash_1.check_match(b"password"));
        assert!(hash_2.check_match(b"password"));
    }

    #[test]
    fn test_use_salt() {
        let hash_1 = Hashed::new(b"password");
        let hash_2 = Hashed::from_salt(b"password", hash_1.salt());
        assert_eq!(hash_1.hash(), hash_2.hash());
        assert!(hash_1.check_match(b"password"));
        assert!(hash_2.check_match(b"password"));
    }

    #[test]
    fn test_from_b64() {
        let hashed = Hashed::from_b64(
            &helpers::bytes_to_b64(test_hash()),
            &helpers::bytes_to_b64(test_salt()),
        )
        .unwrap();
        assert_eq!(hashed.hash(), test_hash());
        assert_eq!(hashed.salt(), test_salt());
    }

    #[test]
    fn test_invalid_hash_length_b64() {
        let hashed_err = Hashed::from_b64(
            &helpers::bytes_to_b64(&[&test_hash()[..], &[255u8]].concat()),
            &helpers::bytes_to_b64(test_salt()),
        )
        .unwrap_err();
        if let Error::InvalidLengthB64Error(location, intended_length, actual_length) = hashed_err {
            assert_eq!(location, String::from("b64_hash"));
            assert_eq!(intended_length, 32);
            assert_eq!(actual_length, 33);
        } else {
            dbg!(&hashed_err);
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_invalid_salt_length_b64() {
        let hashed_err = Hashed::from_b64(
            &helpers::bytes_to_b64(test_hash()),
            &helpers::bytes_to_b64(&test_salt()[1..]),
        )
        .unwrap_err();
        if let Error::InvalidLengthB64Error(location, intended_length, actual_length) = hashed_err {
            assert_eq!(location, String::from("b64_salt"));
            assert_eq!(intended_length, 64);
            assert_eq!(actual_length, 63);
        } else {
            dbg!(&hashed_err);
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_to_from_b64() {
        let hashed_1 = Hashed::new(b"hello, world!");

        let hash_b64 = hashed_1.hash_as_b64();
        let salt_b64 = hashed_1.salt_as_b64();
        let hashed_2 = Hashed::from_b64(&hash_b64, &salt_b64).unwrap();

        assert!(hashed_1.check_match(b"hello, world!"));
        assert!(hashed_2.check_match(b"hello, world!"));
    }
}
