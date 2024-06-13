use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};
use std::io::{Error, ErrorKind};

const HASH_STRING_INVALID_INPUT_MSG: &str = "Input string is not ASCII.";

/// The possible hash functions that dgruft can use.
pub enum HashFn {
    /// SHA-256 from [sha2] crate.
    Sha256,
}

/// A hashed string.
pub struct Hashed {
    string: String,
    hash_fn: HashFn,
}
impl Hashed {
    /// Create a new base 64 [Hashed] using the given [HashFn].
    pub fn hash_string(input: &str, hash_fn: HashFn) -> Result<Self, Error> {
        if input.is_ascii() {
            let hash = Sha256::digest(input.as_bytes());
            let base64_hash = Base64::encode_string(&hash);
            Ok(Self {
                string: base64_hash,
                hash_fn,
            })
        } else {
            Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                HASH_STRING_INVALID_INPUT_MSG,
            ))
        }
    }
}
