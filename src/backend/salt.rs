//! Functionality centred around the [Salt] struct.
use base64ct::{Base64, Encoding};
use rand::{distributions::Standard, Rng};

use std::io::{Error, ErrorKind};

use crate::helpers::is_base64;

#[derive(Debug)]
/// A cryptographic salt utilised for password storage.
pub struct Salt {
    bytes: Vec<u8>,
    string: String,
}
impl Salt {
    /// Generate a random [Salt] of a given length.
    pub fn new(length: usize) -> Self {
        let bytes: Vec<u8> = rand::thread_rng()
            .sample_iter(&Standard)
            .take(length)
            .collect();
        // let string = bytes.iter().map(|byte| char::from(*byte)).collect();
        let string = Base64::encode_string(&bytes);
        Salt { bytes, string }
    }

    /// Read a [Salt] from a given string.
    pub fn from_string(string: &str) -> std::io::Result<Self> {
        if is_base64(string) {
            match Base64::decode_vec(string) {
                Ok(bytes) => Ok(Self {
                    bytes,
                    string: string.to_owned(),
                }),
                Err(e) => Err(Error::new(ErrorKind::Other, e.to_string())),
            }
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "{} is not a valid standard base 64 string.",
                    string.to_owned()
                ),
            ))
        }
    }

    /// Read a [Salt] from a given byte vector.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            string: Base64::encode_string(bytes),
        }
    }

    /// Get this salt in bytes form.
    pub fn get_bytes(&self) -> &Vec<u8> {
        &self.bytes
    }

    /// Get this salt in alphanumeric ASCII string form.
    pub fn get_str(&self) -> &str {
        &self.string
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_salt() {
        let salt = Salt::new(16);
        assert_eq!(Base64::encode_string(salt.get_bytes()), salt.get_str());
        assert_eq!(
            salt.get_bytes(),
            &Base64::decode_vec(salt.get_str()).unwrap()
        );
    }

    #[test]
    fn test_from_string() {
        let test_string = "aGVsbG8gd29ybGQ=";
        let test_bytes = vec![104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
        let salt = Salt::from_string(test_string).unwrap();
        assert_eq!(&test_bytes, salt.get_bytes());
        assert_eq!(test_string, salt.get_str());
    }

    #[test]
    fn test_from_bytes() {
        let test_string = "aGVsbG8gd29ybGQ=";
        let test_bytes = vec![104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
        let salt = Salt::from_bytes(&test_bytes);
        assert_eq!(&test_bytes, salt.get_bytes());
        assert_eq!(test_string, salt.get_str());
    }
}
