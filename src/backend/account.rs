//! Functionality for individual dgruft user accounts.
use color_eyre::eyre::{self, eyre};

use super::{
    credential::Credential,
    encryption::encrypted::{new_rand_key, Aes256Key, Encrypted, TryIntoEncrypted},
    file_data::FileData,
    hashing::hashed::{Hash, Hashed, IntoHashed, Salt},
};

/// A `dgruft` account with a username, password, and encryption key. Each `dgruft` user has an
/// account. The account's `password` serves as the primary authenticator.
///
/// ### Role of the `password`
///
/// - The `password`, when [Hashed] a single time through PBKDF2, serves as the [Aes256Key] for
/// this account's `key`, the [Aes256Key] used to encrypt and decrypt all [Credential],
/// [FileData], and [FileData] contents owned by this account.
///
/// - The double-[Hashed] `password` is stored in the `dgruft` database. When logging in, the
/// user's entered password is compared against this one to verify that the correct password was
/// entered.
pub struct Account {
    username: String,
    password: String,
    hashed_password: Hashed<32, 64>,
    dbl_hashed_password: Hashed<32, 64>,
    key: Aes256Key,
    encrypted_key: Encrypted,
}
// TODO: Ideally, all interactions with Accounts, FileDatas, Credentials, etc. should be only
// through the Vault.
impl Account {
    /// Create a new [Account] from a username and a password.
    pub fn new(username: &str, password: &str) -> eyre::Result<Self> {
        // Generate a random [Aes256Key]. This key is used to encrypt and decrypt all this
        // account's data. It never changes, even when the password is changed.
        let key: Aes256Key = new_rand_key();

        // Hash the password once. This [Hashed] password is used as the [Aes256Key] to encrypt and
        // decrypt this account's `key`.
        let hashed_password = password.into_hashed_rand_salt();

        // Use the hashed password as the key to encrypt the encryption key.
        let encrypted_key = key.try_encrypt_with_key(*hashed_password.hash())?;

        // Hash the hashed password to store it.
        let dbl_hashed_password = hashed_password.hash().into_hashed_rand_salt();

        Ok(Self {
            username: username.to_owned(),
            password: password.to_owned(),
            hashed_password,
            dbl_hashed_password,
            key,
            encrypted_key,
        })
    }

    /// Get the `username` of this [Account].
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the `password` of this [Account].
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Get the `hashed_password` of this [Account].
    pub fn hashed_password(&self) -> &Hashed<32, 64> {
        &self.hashed_password
    }

    /// Get the `dbl_hashed_password` of this [Account].
    pub fn dbl_hashed_password(&self) -> &Hashed<32, 64> {
        &self.dbl_hashed_password
    }

    /// Get the `key` of this [Account].
    pub fn key(&self) -> &Aes256Key {
        &self.key
    }

    /// Get the `encrypted_key` of this [Account].
    pub fn encrypted_key(&self) -> &Encrypted {
        &self.encrypted_key
    }
}
