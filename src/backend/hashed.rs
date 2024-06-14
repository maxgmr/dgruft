//! Functionality related to hashing.
use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};
use std::io::{Error, ErrorKind, Result};

use crate::backend::salt;
use crate::helpers::is_base64;

const HASH_STRING_INVALID_INPUT_MSG: &str = "Input string is not ASCII.";

/// The possible hash functions that dgruft can use.
#[derive(Debug, Clone, Copy)]
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
    /// Create a new base 64 [Hashed] using the given [HashFn], optionally with a given [salt::Salt].
    pub fn new(input: &str, hash_fn: HashFn, salt_opt: Option<&salt::Salt>) -> Result<Self> {
        if input.is_ascii() {
            let mut data = input.to_owned();
            if let Some(salt) = &salt_opt {
                data.push_str(salt.get_str());
            }
            let hash = Sha256::digest(data.as_bytes());
            let base64_hash = Base64::encode_string(&hash);
            Ok(Self {
                bytes: hash.to_vec(),
                string: base64_hash,
                hash_fn,
                salt: salt_opt.cloned(),
            })
        } else {
            Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                HASH_STRING_INVALID_INPUT_MSG,
            ))
        }
    }

    /// Read a [Hashed] from a given string.
    pub fn from_string(
        hash_str: &str,
        salt: Option<salt::Salt>,
        hash_fn: HashFn,
    ) -> std::io::Result<Self> {
        if is_base64(hash_str) {
            match Base64::decode_vec(hash_str) {
                Ok(bytes) => Ok(Self {
                    bytes,
                    string: hash_str.to_owned(),
                    hash_fn,
                    salt,
                }),
                Err(e) => Err(Error::new(ErrorKind::Other, e.to_string())),
            }
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "{} is not a valid standard base 64 string.",
                    hash_str.to_owned()
                ),
            ))
        }
    }

    /// Read a [Hashed] from a given byte vector.
    pub fn from_bytes(bytes: &[u8], salt: Option<salt::Salt>, hash_fn: HashFn) -> Self {
        Self {
            bytes: bytes.to_vec(),
            string: Base64::encode_string(bytes),
            hash_fn,
            salt,
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
    use hex_literal::hex;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_hash_sha256() {
        let hash_1 = Hashed::new("password", HashFn::Sha256, None).unwrap();
        let hash_2 = Hashed::new("password", HashFn::Sha256, None).unwrap();
        assert_eq!(hash_1.get_str(), hash_2.get_str());
        assert_eq!(hash_1.get_bytes(), hash_2.get_bytes());

        let blank_sha256_b64 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        let hash_blank = Hashed::new("", HashFn::Sha256, None).unwrap();
        assert_eq!(hash_blank.get_str(), blank_sha256_b64);

        let hw = Hashed::new("hello world", HashFn::Sha256, None).unwrap();
        dbg!(hw.get_bytes());
        dbg!(&hw.get_bytes()[..]);
        assert_eq!(
            hw.get_bytes()[..],
            hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")[..]
        )
    }

    #[test]
    fn test_hash_sha256_salt() {
        let hash_1 = Hashed::new("password", HashFn::Sha256, None).unwrap();
        let hash_s1 = Hashed::new("password", HashFn::Sha256, Some(&salt::Salt::new(16))).unwrap();
        let hash_s2 = Hashed::new("password", HashFn::Sha256, Some(&salt::Salt::new(16))).unwrap();

        assert_ne!(hash_1.get_str(), hash_s1.get_str());
        assert_ne!(hash_s1.get_str(), hash_s2.get_str());
    }

    #[test]
    fn test_non_ascii() {
        let err = Hashed::new("привет", HashFn::Sha256, None).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_compare_salted_hash() {
        let password = "myawesomepassword";
        let salt = salt::Salt::new(16);
        let salted_hash_1 = Hashed::new(password, HashFn::Sha256, Some(&salt)).unwrap();
        let salted_hash_2 = Hashed::new(password, HashFn::Sha256, Some(&salt)).unwrap();

        assert_eq!(salted_hash_1.get_str(), salted_hash_2.get_str());
    }
}
