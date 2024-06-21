//! Functionality related to encryption.
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};

use crate::{error::Error, helpers};

/// An encrypted string.
#[derive(Debug, Clone)]
pub struct Encrypted {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
}
impl Encrypted {
    /// Encrypt a given byte array using a key.
    pub fn new(content: &[u8], key: &[u8; 32]) -> Result<Self, Error> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(key.into());
        match cipher.encrypt(&nonce, content) {
            Ok(ciphertext) => Ok(Self {
                ciphertext,
                nonce: nonce.to_vec().try_into().unwrap(),
            }),
            Err(e) => Err(Error::EncryptionError(e.to_string())),
        }
    }

    /// Encrypt a given byte array using a key and a given nonce.
    pub fn from_nonce(content: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Self, Error> {
        let cipher = Aes256Gcm::new(key.into());
        match cipher.encrypt(nonce.into(), content) {
            Ok(ciphertext) => Ok(Self {
                ciphertext,
                nonce: nonce.to_vec().try_into().unwrap(),
            }),
            Err(e) => Err(Error::EncryptionError(e.to_string())),
        }
    }

    /// Read an [Encrypted] from encrypted ciphertext.
    pub fn from_bytes(ciphertext: &[u8], nonce: &[u8; 12]) -> Self {
        Self {
            ciphertext: ciphertext.to_vec(),
            nonce: *nonce,
        }
    }

    /// Read an [Encrypted] from a base-64 string.
    pub fn from_b64(b64_ciphertext: &str, b64_nonce: &str) -> Result<Self, Error> {
        Ok(Self {
            ciphertext: helpers::b64_to_bytes(b64_ciphertext)?,
            nonce: helpers::b64_to_fixed::<&str, 12>(b64_nonce, "b64_nonce")?,
        })
    }

    /// Decrypt this [Encrypted] using its key.
    pub fn decrypt(&self, key: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = Aes256Gcm::new(key.into());
        match cipher.decrypt(self.nonce().into(), self.ciphertext()) {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(Error::DecryptionError(e.to_string())),
        }
    }

    // GETTERS

    /// Return the ciphertext of this [Encrypted].
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Return the ciphertext of this [Encrypted] as a base-64 string.
    pub fn ciphertext_as_b64(&self) -> String {
        helpers::bytes_to_b64(&self.ciphertext)
    }

    /// Return the nonce of this [Encrypted].
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// Return the nonce of this [Encrypted] as a base-64 string.
    pub fn nonce_as_b64(&self) -> String {
        helpers::bytes_to_b64(&self.nonce)
    }
}

/// Generate a new key to be used for AES-256 encryption & decryption.
pub fn new_key(slice: Option<&[u8; 32]>) -> [u8; 32] {
    if let Some(slice) = slice {
        // Generate key from slice
        let key: &Key<Aes256Gcm> = slice.into();
        key.to_vec().try_into().unwrap()
    } else {
        // Randomly generate key
        Aes256Gcm::generate_key(OsRng).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_new_key() {
        let key_1 = super::new_key(None);
        let key_2 = super::new_key(Some(&key_1));
        assert_eq!(key_1, key_2);
    }

    #[test]
    fn test_aes256() {
        let plaintext = b"Hello, world!";
        let key = new_key(None);
        let encrypted = Encrypted::new(plaintext, &key).unwrap();
        let decrypted_text = encrypted.decrypt(&key).unwrap();
        assert_eq!(&plaintext[..], decrypted_text);
    }

    #[test]
    fn test_aes256_utf8() {
        let plaintext = "你好";
        let key = new_key(None);
        let encrypted = Encrypted::new(plaintext.as_bytes(), &key).unwrap();
        let decrypted_text = encrypted.decrypt(&key).unwrap();
        assert_eq!(plaintext.as_bytes(), decrypted_text);
        assert_eq!("你好", std::str::from_utf8(&decrypted_text).unwrap());
    }

    #[test]
    fn test_to_from_b64() {
        let plaintext = "привет";
        let key = new_key(None);
        let encrypted_1 = Encrypted::new(plaintext.as_bytes(), &key).unwrap();

        let ciphertext_b64 = encrypted_1.ciphertext_as_b64();
        let nonce_b64 = encrypted_1.nonce_as_b64();
        let encrypted_2 = Encrypted::from_b64(&ciphertext_b64, &nonce_b64).unwrap();

        let decrypted_1 = encrypted_1.decrypt(&key).unwrap();
        let decrypted_2 = encrypted_2.decrypt(&key).unwrap();

        assert_eq!(decrypted_1, decrypted_2);
    }
}
