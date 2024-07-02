//! Functionality related to hashing different types.
use camino::{Utf8Path, Utf8PathBuf};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};

use super::{
    super::encryption::encrypted::{Aes256Key, Aes256Nonce},
    hashed::*,
};

/// Implementors of this trait can be hashed and salted into a [Hashed].
///
/// Most implementations of this trait implement *only* [IntoHashed::into_hashed_with_salt] and
/// [IntoHashed::check_match].
///
/// The easiest way to implement [IntoHashed::into_hashed_with_salt] is to convert the type to a
/// `u8` slice then return [Hashed::hash_with_salt].
///
/// The easiest way to implement [IntoHashed::check_match] is to convert the type to a `u8` slice
/// then return [Hashed::check_match].
pub trait IntoHashed<const H: usize, const S: usize> {
    /// Hash and salt using a randomly-generated salt.
    #[allow(dead_code)]
    fn into_hashed_rand_salt(self) -> Hashed<H, S>
    where
        Self: Sized,
    {
        let mut salt: Salt<S> = [0u8; S];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut salt);
        self.into_hashed_with_salt(salt)
    }

    /// Hash and salt using a given salt.
    fn into_hashed_with_salt(self, salt: Salt<S>) -> Hashed<H, S>;

    /// Check whether the given entity, when hashed, matches the given salt.
    #[allow(dead_code)]
    fn check_match(self, hashed: &Hashed<H, S>) -> bool;
}

// Implementations for some external types.
macro_rules! impl_into_hashed_byte_vec {
    ($($t:ty),+) => {
        $(impl<const H: usize, const S: usize> IntoHashed<H, S> for $t {
            fn into_hashed_with_salt(self, salt: Salt<S>) -> Hashed<H, S> {
                let byte_vec: Vec<u8> = self.into();
                Hashed::hash_with_salt(&byte_vec, salt)
            }

            fn check_match(self, hashed: &Hashed<H, S>) -> bool {
                let byte_vec: Vec<u8> = self.into();
                hashed.check_match(&byte_vec)
            }
        })*
    }
}
impl_into_hashed_byte_vec!(Vec<u8>, &[u8], String, &str, Aes256Key, Aes256Nonce);

macro_rules! impl_into_hashed_camino {
    ($($t:ty),+) => {
        $(impl<const H: usize, const S: usize> IntoHashed<H, S> for $t {
            fn into_hashed_with_salt(self, salt: Salt<S>) -> Hashed<H, S> {
                let path_string = self.to_string();
                let byte_slice: &[u8] = path_string.as_bytes();
                Hashed::hash_with_salt(byte_slice, salt)
            }

            fn check_match(self, hashed: &Hashed<H, S>) -> bool {
                let path_string = self.to_string();
                let byte_slice: &[u8] = path_string.as_bytes();
                hashed.check_match(byte_slice)
            }
        })*
    }
}
impl_into_hashed_camino!(Utf8PathBuf, &Utf8Path);
