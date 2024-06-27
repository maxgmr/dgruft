//! Functionality for credentials stored by `dgruft` user accounts.
use color_eyre::eyre;

use super::encryption::encrypted::{Aes256Key, Encrypted, TryFromEncrypted, TryIntoEncrypted};

/// User-defined login information for various sites and services. The main data unit of `dgruft`'s
/// "password bank" functionality.
///
/// ### Fields
///
/// - `owner_username`: The username of the [Account] that owns this [Credential].
///
/// - `encrypted_name`: The [Encrypted] name of this [Credential].
///
/// - `encrypted_username`: The [Encrypted] username of this [Credential]. This is the username of
/// the [Credential] login information, *not* the `dgruft` [Account] username.
///
/// - `encrypted_password`: The [Encrypted] password of this [Credential]. This is the password of
/// the [Credential] login information, *not* the `dgruft` [Account] username.
///
/// - `encrypted_notes`: The [Encrypted] notes of this [Credential]. These are user-defined notes
/// related to the [Credential] information. They can be any text the user wants.
#[derive(Debug, PartialEq, Eq)]
pub struct Credential {
    owner_username: String,
    encrypted_name: Encrypted,
    encrypted_username: Encrypted,
    encrypted_password: Encrypted,
    encrypted_notes: Encrypted,
}
impl Credential {
    /// Create a new [Credential].
    pub fn try_new(
        owner_username: &str,
        encryption_key: Aes256Key,
        name: &str,
        username: &str,
        password: &str,
        notes: &str,
    ) -> eyre::Result<Self> {
        let encrypted_name = name.try_encrypt_with_key(encryption_key)?;
        let encrypted_username = username.try_encrypt_with_key(encryption_key)?;
        let encrypted_password = password.try_encrypt_with_key(encryption_key)?;
        let encrypted_notes = notes.try_encrypt_with_key(encryption_key)?;
        Ok(Self {
            owner_username: owner_username.to_owned(),
            encrypted_name,
            encrypted_username,
            encrypted_password,
            encrypted_notes,
        })
    }

    /// Create a [Credential] from its fields.
    pub fn from_fields(
        owner_username: String,
        encrypted_name: Encrypted,
        encrypted_username: Encrypted,
        encrypted_password: Encrypted,
        encrypted_notes: Encrypted,
    ) -> Self {
        Self {
            owner_username,
            encrypted_name,
            encrypted_username,
            encrypted_password,
            encrypted_notes,
        }
    }

    /// Get the `owner_username` of this [Credential].
    pub fn owner_username(&self) -> &str {
        &self.owner_username
    }

    /// Get the `encrypted_name` of this [Credential].
    pub fn encrypted_name(&self) -> &Encrypted {
        &self.encrypted_name
    }

    /// Get the `encrypted_username` of this [Credential].
    pub fn encrypted_username(&self) -> &Encrypted {
        &self.encrypted_username
    }

    /// Get the `encrypted_password` of this [Credential].
    pub fn encrypted_password(&self) -> &Encrypted {
        &self.encrypted_password
    }

    /// Get the `encrypted_notes` of this [Credential].
    pub fn encrypted_notes(&self) -> &Encrypted {
        &self.encrypted_notes
    }

    /// Decrypt the `encrypted_name` of this [Credential].
    pub fn name<T: TryFromEncrypted>(&self, key: Aes256Key) -> eyre::Result<T> {
        T::try_decrypt(&self.encrypted_name, key)
    }

    /// Decrypt the `encrypted_username` of this [Credential].
    pub fn username<T: TryFromEncrypted>(&self, key: Aes256Key) -> eyre::Result<T> {
        T::try_decrypt(&self.encrypted_username, key)
    }

    /// Decrypt the `encrypted_password` of this [Credential].
    pub fn password<T: TryFromEncrypted>(&self, key: Aes256Key) -> eyre::Result<T> {
        T::try_decrypt(&self.encrypted_password, key)
    }

    /// Decrypt the `encrypted_notes` of this [Credential].
    pub fn notes<T: TryFromEncrypted>(&self, key: Aes256Key) -> eyre::Result<T> {
        T::try_decrypt(&self.encrypted_notes, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pretty_assertions::assert_eq;

    use crate::backend::encryption::encrypted::new_rand_key;

    const TEST_OWNER_USERNAME: &str = "my_dgruft_acc";
    const TEST_NAME: &str = "My Schploggy™ Login Info";
    const TEST_USERNAME: &str = "my_username_123";
    const TEST_PASSWORD: &str = "iLoveSchploggy123!";
    const TEST_NOTES: &str = "Remember to change your password every six months!";

    #[test]
    fn new_credential() {
        let key = new_rand_key();
        let creds = Credential::try_new(
            TEST_OWNER_USERNAME,
            key,
            TEST_NAME,
            TEST_USERNAME,
            TEST_PASSWORD,
            TEST_NOTES,
        )
        .unwrap();

        assert_eq!(TEST_OWNER_USERNAME, creds.owner_username());
        assert_eq!(TEST_NAME, &creds.name::<String>(key).unwrap());
        assert_eq!(
            TEST_USERNAME.as_bytes(),
            &creds.username::<Vec<u8>>(key).unwrap()
        );
        assert_eq!(TEST_PASSWORD, &creds.password::<String>(key).unwrap());
        assert_eq!(TEST_NOTES, &creds.notes::<String>(key).unwrap());
    }
}
