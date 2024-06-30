//! Functionality for individual dgruft user accounts.
use color_eyre::eyre::{self, eyre};

use super::{
    encryption::encrypted::{
        new_rand_key, Aes256Key, Encrypted, TryFromEncrypted, TryIntoEncrypted,
    },
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

    /// Unlock this [Account] into an [UnlockedAccount] using its password.
    pub fn unlock(&self, password: &str) -> eyre::Result<UnlockedAccount> {
        let hashed_password = password.into_hashed_with_salt(self.password_salt);
        let dbl_hashed_password = hashed_password
            .hash()
            .into_hashed_with_salt(*self.dbl_hashed_password.salt());

        // Ensure passwords match
        if dbl_hashed_password.hash() != self.dbl_hashed_password.hash() {
            return Err(eyre!("Incorrect password."));
        }

        // Password OK. Get encryption key.
        let key = Aes256Key::try_decrypt(&self.encrypted_key, *hashed_password.hash())?;

        Ok(UnlockedAccount {
            username: self.username.to_owned(),
            password: password.to_owned(),
            hashed_password,
            dbl_hashed_password,
            key,
            encrypted_key: self.encrypted_key.clone(),
        })
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

/// An [Account] with all its fields accessible. This data should *never* be written to the disk or
/// recorded in any other way!
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnlockedAccount {
    username: String,
    password: String,
    hashed_password: Hashed<32, 64>,
    dbl_hashed_password: Hashed<32, 64>,
    key: Aes256Key,
    encrypted_key: Encrypted,
}
impl UnlockedAccount {
    /// Change the `password` of this [UnlockedAccount].
    ///
    /// The encryption key itself remains unchanged.
    pub fn change_password(&mut self, new_password: &str) -> eyre::Result<()> {
        let new_hashed_password = new_password.into_hashed_rand_salt();
        let new_encrypted_key = self.key.try_encrypt_with_key(*new_hashed_password.hash())?;
        let new_dbl_hashed_password = new_hashed_password.hash().into_hashed_rand_salt();

        self.hashed_password = new_hashed_password;
        self.encrypted_key = new_encrypted_key;
        self.dbl_hashed_password = new_dbl_hashed_password;

        Ok(())
    }

    /// Return the `username` of this [UnlockedAccount].
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Return the `password` of this [UnlockedAccount].
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Return the `hashed_password` of this [UnlockedAccount].
    pub fn hashed_password(&self) -> &Hashed<32, 64> {
        &self.hashed_password
    }

    /// Return the `dbl_hashed_password` of this [UnlockedAccount].
    pub fn dbl_hashed_password(&self) -> &Hashed<32, 64> {
        &self.dbl_hashed_password
    }

    /// Return the `key` of this [UnlockedAccount].
    pub fn key(&self) -> Aes256Key {
        self.key
    }

    /// Return the `encrypted_key` of this [UnlockedAccount].
    pub fn encrypted_key(&self) -> &Encrypted {
        &self.encrypted_key
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn unlock() {
        let username = "mr_test";
        let password = "123";
        let account = Account::new(username, password).unwrap();

        let _ = account.unlock("1234").unwrap_err();
        let unlocked = account.unlock("123").unwrap();
        let unlocked_again = account.unlock("123").unwrap();

        assert_eq!(unlocked.username(), username);
        assert_eq!(unlocked.password(), password);

        assert_eq!(unlocked, unlocked_again);
    }
}
