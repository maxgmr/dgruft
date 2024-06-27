//! Functionality related to the [Hashed] struct.
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// Re-export traits
pub use super::traits::*;

/// A fixed-length, H-byte cryptographic hash.
pub type Hash<const H: usize> = [u8; H];

/// A fixed-length, S-byte cryptographic salt.
pub type Salt<const S: usize> = [u8; S];

/// H bytes hashed and salted using PBKDF2-HMAC-SHA256 & a S-byte salt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashed<const H: usize, const S: usize> {
    hash: Hash<H>,
    salt: Salt<S>,
}
impl<const H: usize, const S: usize> Hashed<H, S> {
    const NUM_ITERATIONS: u32 = 50_000;

    /// Hash and salt a byte slice using a given salt.
    pub fn hash_with_salt(byte_slice: &[u8], salt: Salt<S>) -> Self {
        let mut hash: Hash<H> = [0u8; H];
        pbkdf2_hmac::<Sha256>(byte_slice, &salt, Self::NUM_ITERATIONS, &mut hash);

        Self { hash, salt }
    }

    /// Create a [Hashed] from its fields.
    pub fn from_fields(hash: Hash<H>, salt: Salt<S>) -> Self {
        Self { hash, salt }
    }

    /// Check whether the given bytes match the bytes used to make this [Hashed].
    pub fn check_match(&self, byte_slice: &[u8]) -> bool {
        let hashed_input = Self::hash_with_salt(byte_slice, self.salt);
        self.hash() == hashed_input.hash()
    }

    /// Return the [Hash] of this [Hashed].
    pub fn hash(&self) -> &Hash<H> {
        &self.hash
    }

    /// Return the [Salt] of this [Hashed].
    pub fn salt(&self) -> &Salt<S> {
        &self.salt
    }
}

#[cfg(test)]
mod tests {
    use camino::Utf8PathBuf;
    use pretty_assertions::{assert_eq, assert_ne};

    use super::{super::traits::*, *};

    const TEST_BYTES: &[u8] = b"password";
    const TEST_BYTES_DIFFERENT: &[u8] = b"passwore";
    const TEST_UTF8: &str = "三思而后行。";
    const TEST_PATH_STR: &str = "src/backend/hashing/hashed.rs";

    fn test_utf8_path_buf() -> Utf8PathBuf {
        Utf8PathBuf::from(TEST_PATH_STR)
    }

    #[test]
    fn pbkdf2_consistency() {
        let hash_1: Hashed<32, 64> = TEST_BYTES.into_hashed_rand_salt();
        let hash_2: Hashed<32, 64> = TEST_BYTES.into_hashed_rand_salt();
        let hash_1_dupe: Hashed<32, 64> = TEST_BYTES.into_hashed_with_salt(*hash_1.salt());

        assert_eq!(hash_1, hash_1_dupe);
        assert_ne!(hash_1, hash_2);

        assert!(TEST_BYTES.check_match(&hash_1));
        assert!(TEST_BYTES.check_match(&hash_2));
        assert!(TEST_BYTES.check_match(&hash_1_dupe));

        assert!(!TEST_BYTES_DIFFERENT.check_match(&hash_1));
    }

    #[test]
    fn pbkdf2_consistency_diff_lengths() {
        let hash_10: Hashed<10, 32> = TEST_UTF8.into_hashed_rand_salt();
        let salt = *hash_10.salt();
        let hash_17: Hashed<17, 32> = TEST_UTF8.into_hashed_with_salt(salt);
        let hash_123: Hashed<123, 32> = TEST_UTF8.into_hashed_with_salt(salt);

        assert!(TEST_UTF8.check_match(&hash_10));
        assert!(TEST_UTF8.check_match(&hash_17));
        assert!(TEST_UTF8.check_match(&hash_123));
    }

    #[test]
    fn hash_utf8_paths() {
        let hashed_path_buf: Hashed<32, 64> = test_utf8_path_buf().into_hashed_rand_salt();
        let salt = *hashed_path_buf.salt();
        let hashed_path: Hashed<32, 64> =
            test_utf8_path_buf().as_path().into_hashed_with_salt(salt);
        let hashed_str: Hashed<32, 64> = TEST_PATH_STR.into_hashed_with_salt(salt);
        let hashed_bytes: Hashed<32, 64> = TEST_PATH_STR.as_bytes().into_hashed_with_salt(salt);

        assert_eq!(hashed_path, hashed_path_buf);
        assert_eq!(hashed_path_buf, hashed_str);
        assert_eq!(hashed_path_buf, hashed_bytes);

        assert!(test_utf8_path_buf().check_match(&hashed_path_buf));
        assert!(test_utf8_path_buf().as_path().check_match(&hashed_path_buf));
        assert!(TEST_PATH_STR.check_match(&hashed_path_buf));
        assert!(TEST_PATH_STR.as_bytes().check_match(&hashed_path_buf));
    }
}
