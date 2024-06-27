//! Functionality for individual dgruft user accounts.
use color_eyre::eyre;

use super::{
    encryption::encrypted::{new_rand_key, Aes256Key, Encrypted, TryIntoEncrypted},
    hashing::hashed::{Hashed, IntoHashed, Salt},
};

/// A `dgruft` account with a username, password, and encryption key. Each `dgruft` user has an
/// account. The account's `password` serves as the primary authenticator.
///
/// ### Role of the `password`
///
/// - The `password`, when [Hashed] a single time through PBKDF2, serves as the [Aes256Key] for
///     this account's `key`, the [Aes256Key] used to encrypt and decrypt all [Credential],
///     [FileData], and [FileData] contents owned by this account.
///
/// - The double-[Hashed] `password` is stored in the `dgruft` database. When logging in, the
///     user's entered password is compared against this one to verify that the correct password was
///     entered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    username: String,
    password_salt: Salt<64>,
    dbl_hashed_password: Hashed<32, 64>,
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
            password_salt: *hashed_password.salt(),
            dbl_hashed_password,
            encrypted_key,
        })
    }

    /// Create an [Account] from its fields.
    pub fn from_fields(
        username: String,
        password_salt: Salt<64>,
        dbl_hashed_password: Hashed<32, 64>,
        encrypted_key: Encrypted,
    ) -> Self {
        Self {
            username,
            password_salt,
            dbl_hashed_password,
            encrypted_key,
        }
    }

    /// Get the `username` of this [Account].
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the `password_salt` of this [Account].
    pub fn password_salt(&self) -> &Salt<64> {
        &self.password_salt
    }

    /// Get the `dbl_hashed_password` of this [Account].
    pub fn dbl_hashed_password(&self) -> &Hashed<32, 64> {
        &self.dbl_hashed_password
    }

    /// Get the `encrypted_key` of this [Account].
    pub fn encrypted_key(&self) -> &Encrypted {
        &self.encrypted_key
    }
}
