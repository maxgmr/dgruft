//! Functionality centred around the [Salt] struct.
use rand::{distributions::Alphanumeric, Rng};

#[derive(Debug)]
/// A cryptographic salt utilised for password storage.
pub struct Salt {
    bytes: Vec<u8>,
    string: String,
}
impl Salt {
    /// Generate a random alphanumeric salt of a given length.
    pub fn new(length: usize) -> Self {
        let bytes: Vec<u8> = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .collect();
        let string = bytes.iter().map(|byte| char::from(*byte)).collect();
        Salt { bytes, string }
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
