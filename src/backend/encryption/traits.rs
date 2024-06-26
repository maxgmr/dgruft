//! Functionality related to encrypting and decrypting different types.
use aes_gcm::{
    aead::{AeadCore, OsRng},
    Aes256Gcm,
};
use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{self, eyre};

use super::encrypted::*;

/// Implementors of this trait can be AES-256 encrypted & converted into an [Encrypted].
///
/// Most implementations of this trait implement *only* [TryIntoEncrypted::try_encrypt_with_both].
/// The easiest way to do this is to convert the type to a `u8` slice then return
/// [Encrypted::try_encrypt_bytes_key_nonce].
pub trait TryIntoEncrypted {
    /// Encrypt using a randomly-generated [Aes256Key] and [Aes256Nonce].
    fn try_encrypt_new_key(self) -> eyre::Result<(Encrypted, Aes256Key)>
    where
        Self: Sized,
    {
        let key = new_rand_key();
        Ok((self.try_encrypt_with_key(key)?, key))
    }

    /// Encrypt using a given [Aes256Key] and randomly-generated [Aes256Nonce].
    fn try_encrypt_with_key(self, key: Aes256Key) -> eyre::Result<Encrypted>
    where
        Self: Sized,
    {
        let nonce: Aes256Nonce = Aes256Gcm::generate_nonce(&mut OsRng).into();
        self.try_encrypt_with_both(key, nonce)
    }

    /// Encrypt using a given [Aes256Key] and [Aes256Nonce].
    fn try_encrypt_with_both(self, key: Aes256Key, nonce: Aes256Nonce) -> eyre::Result<Encrypted>
    where
        Self: Sized;
}

// Implementations for some external types.
macro_rules! impl_to_encrypted_byte_vec {
    ($($t:ty),+) => {
        $(impl TryIntoEncrypted for $t {
            fn try_encrypt_with_both(
                self,
                key: Aes256Key,
                nonce: Aes256Nonce,
            ) -> eyre::Result<Encrypted> {
                let byte_vec: Vec<u8> = match self.try_into() {
                    Ok(byte_vec) => byte_vec,
                    Err(_) => return Err(
                        eyre!("TryIntoEncrypted: Failed to convert to byte slice.")
                    ),
                };
                Encrypted::try_encrypt_bytes_key_nonce(&byte_vec, key, nonce)
            }
        })*
    }
}
impl_to_encrypted_byte_vec!(Vec<u8>, &[u8], String, &str, Aes256Key, Aes256Nonce);

macro_rules! impl_to_encrypted_camino {
    ($($t:ty),+) => {
        $(impl TryIntoEncrypted for $t {
            fn try_encrypt_with_both(
                self,
                key: Aes256Key,
                nonce: Aes256Nonce
            ) -> eyre::Result<Encrypted> {
                let path_string = self.to_string();
                let byte_slice: &[u8] = path_string.as_bytes();
                Encrypted::try_encrypt_bytes_key_nonce(byte_slice, key, nonce)
            }
        })*
    }
}
impl_to_encrypted_camino!(Utf8PathBuf, &Utf8Path);

/// Implementors of this trait can be AES-256 decrypted & converted from an [Encrypted].
///
/// Most implementors of this trait implement [TryFromEncrypted::try_decrypt] by getting the result
/// of [Encrypted::try_decrypt_bytes], then converting the resulting [Vec<u8>] into the
/// implementing type.
pub trait TryFromEncrypted {
    /// Decrypt the [Encrypted] into the implementing type.
    fn try_decrypt(encrypted: &Encrypted, key: Aes256Key) -> eyre::Result<Self>
    where
        Self: Sized;
}

// Implementations for some external types.
macro_rules! impl_from_encrypted_byte_vec {
    ($($t:ty),+) => {
        $(impl TryFromEncrypted for $t {
            fn try_decrypt(encrypted: &Encrypted, key: Aes256Key) -> eyre::Result<Self> {
                let decrypted_bytes: Vec<u8> = encrypted.try_decrypt_bytes(key)?;
                match Self::try_from(decrypted_bytes) {
                    Ok(decrypted_self) => Ok(decrypted_self),
                    Err(_) => return Err(
                        eyre!("TryFromEncrypted: Failed to convert from byte vector.")
                    ),
                }
            }
        })*
    }
}
impl_from_encrypted_byte_vec!(Vec<u8>, Aes256Key, Aes256Nonce);

macro_rules! impl_from_encrypted_utf8 {
    ($($t:ty),+) => {
        $(impl TryFromEncrypted for $t {
            fn try_decrypt(encrypted: &Encrypted, key: Aes256Key) -> eyre::Result<Self> {
                let decrypted_bytes: Vec<u8> = encrypted.try_decrypt_bytes(key)?;
                match String::from_utf8(decrypted_bytes) {
                    Ok(decrypted_string) => match Self::try_from(decrypted_string) {
                        Ok(decrypted_self) => Ok(decrypted_self),
                        Err(_) => return Err(
                            eyre!("TryFromEncrypted: Failed to convert from String.")
                        ),
                    },
                    Err(_) => return Err(
                        eyre!(
                            "TryFromEncrypted: Failed to convert to String from byte vector."
                        )
                    ),
                }
            }
        })*
    }
}
impl_from_encrypted_utf8!(String, Utf8PathBuf);
