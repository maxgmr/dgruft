//! Functionality related to hashing.
use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};
use std::io::{Error, ErrorKind, Result};

use crate::backend::salt;

const HASH_STRING_INVALID_INPUT_MSG: &str = "Input string is not ASCII.";

/// The possible hash functions that dgruft can use.
#[derive(Debug)]
pub enum HashFn {
    /// SHA-256 from [sha2] crate.
    Sha256,
}

#[derive(Debug)]
/// A hashed string.
pub struct Hashed {
    bytes: Vec<u8>,
    string: String,
    hash_fn: HashFn,
    salt: Option<salt::Salt>,
}
impl Hashed {
    /// Create a new base 64 [Hashed] using the given [HashFn].
    pub fn hash_string(input: &str, hash_fn: HashFn) -> Result<Self> {
        if input.is_ascii() {
            let hash = Sha256::digest(input.as_bytes());
            let base64_hash = Base64::encode_string(&hash);
            Ok(Self {
                bytes: hash.to_vec(),
                string: base64_hash,
                hash_fn,
                salt: None,
            })
        } else {
            Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                HASH_STRING_INVALID_INPUT_MSG,
            ))
        }
    }

    /// Create a new base 64 [Hashed] with a given [salt::Salt].
    pub fn hash_salt_string(input: &str, hash_fn: HashFn, salt: salt::Salt) -> Result<Self> {
        if input.is_ascii() {
            let hash = Sha256::new()
                .chain_update(input.as_bytes())
                .chain_update(salt.get_bytes())
                .finalize();
            let base64_hash = Base64::encode_string(&hash);
            Ok(Self {
                bytes: hash.to_vec(),
                string: base64_hash,
                hash_fn,
                salt: None,
            })
        } else {
            Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                HASH_STRING_INVALID_INPUT_MSG,
            ))
        }
    }

    /// Get the bytes of this [Hashed].
    pub fn get_bytes(&self) -> &Vec<u8> {
        &self.bytes
    }

    /// Get the string contents of this [Hashed].
    pub fn get_str(&self) -> &str {
        &self.string
    }

    /// Get the function used to hash this [Hashed].
    pub fn get_hash_fn(&self) -> &HashFn {
        &self.hash_fn
    }

    /// Get the [salt::Salt] that was added to the original string (if any).
    pub fn get_salt(&self) -> &Option<salt::Salt> {
        &self.salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_hash_sha256() {
        let hash_1 = Hashed::hash_string("password", HashFn::Sha256);
        let hash_2 = Hashed::hash_string("password", HashFn::Sha256);
        assert_eq!(hash_1.unwrap().get_str(), hash_2.unwrap().get_str());

        let blank_sha256 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        let hash_blank = Hashed::hash_string("", HashFn::Sha256).unwrap();
        assert_eq!(hash_blank.get_str(), blank_sha256);
    }

    #[test]
    fn test_hash_sha256_salt() {
        let hash_1 = Hashed::hash_string("password", HashFn::Sha256).unwrap();
        let hash_s1 =
            Hashed::hash_salt_string("password", HashFn::Sha256, salt::Salt::new(16)).unwrap();
        let hash_s2 =
            Hashed::hash_salt_string("password", HashFn::Sha256, salt::Salt::new(16)).unwrap();

        assert_ne!(hash_1.get_str(), hash_s1.get_str());
        assert_ne!(hash_s1.get_str(), hash_s2.get_str());
    }

    #[test]
    fn test_non_ascii() {
        let err = Hashed::hash_string("привет", HashFn::Sha256).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }
}
