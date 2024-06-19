//! Functionality related to reading and writing encrypted stored passwords.
//!
//! These are *stored passwords*, *not* passwords for `dgruft` accounts.
use crate::helpers;
use crate::{backend::encrypted::Encrypted, error::Error};

/// A password with an associated owner dgruft account, a username associated with that password, a
/// name associated with this login info in the dgruft interface, and some personal notes.
#[derive(Debug)]
pub struct Password {
    owner_username: String,
    encrypted_name: Encrypted,
    encrypted_username: Encrypted,
    encrypted_content: Encrypted,
    encrypted_notes: Encrypted,
}
impl Password {
    /// Create a new [Password].
    pub fn new(
        owner_username: &str,
        key: &[u8; 32],
        name: &str,
        username: &str,
        password: &str,
        notes: &str,
    ) -> Result<Self, Error> {
        let owner_username = owner_username.to_owned();
        let encrypted_name = Encrypted::new(name.as_bytes(), key)?;
        let encrypted_username = Encrypted::new(username.as_bytes(), key)?;
        let encrypted_content = Encrypted::new(password.as_bytes(), key)?;
        let encrypted_notes = Encrypted::new(notes.as_bytes(), key)?;
        Ok(Self {
            owner_username,
            encrypted_name,
            encrypted_username,
            encrypted_content,
            encrypted_notes,
        })
    }

    /// Load a [Password] from a [Base64Password]— a set of base-64-encoded strings.
    pub fn from_b64(b64_password: Base64Password) -> Result<Self, Error> {
        let owner_username = helpers::bytes_to_utf8(
            &helpers::b64_to_bytes(&b64_password.b64_owner_username)?,
            "owner_username",
        )?;
        let encrypted_name = Encrypted::from_b64(
            &b64_password.b64_name_ciphertext,
            &b64_password.b64_name_nonce,
        )?;
        let encrypted_username = Encrypted::from_b64(
            &b64_password.b64_username_ciphertext,
            &b64_password.b64_username_nonce,
        )?;
        let encrypted_content = Encrypted::from_b64(
            &b64_password.b64_content_ciphertext,
            &b64_password.b64_content_nonce,
        )?;
        let encrypted_notes = Encrypted::from_b64(
            &b64_password.b64_notes_ciphertext,
            &b64_password.b64_notes_nonce,
        )?;

        Ok(Self {
            owner_username,
            encrypted_name,
            encrypted_username,
            encrypted_content,
            encrypted_notes,
        })
    }

    /// Convert this [Password] to a [Base64Password] for storage.
    pub fn to_b64(&self) -> Base64Password {
        Base64Password {
            b64_owner_username: helpers::bytes_to_b64(self.owner_username().as_bytes()),
            b64_name_ciphertext: self.encrypted_name().ciphertext_as_b64(),
            b64_username_ciphertext: self.encrypted_username().ciphertext_as_b64(),
            b64_content_ciphertext: self.encrypted_content().ciphertext_as_b64(),
            b64_notes_ciphertext: self.encrypted_notes().ciphertext_as_b64(),
            b64_name_nonce: self.encrypted_name().nonce_as_b64(),
            b64_username_nonce: self.encrypted_username().nonce_as_b64(),
            b64_content_nonce: self.encrypted_content().nonce_as_b64(),
            b64_notes_nonce: self.encrypted_notes().nonce_as_b64(),
        }
    }

    // GETTERS

    /// Return the owner username of this [Password]. This is the `dgruft` username, *not* the
    /// username associated with the password itself.
    pub fn owner_username(&self) -> &str {
        &self.owner_username
    }

    /// Return the encrypted name of this [Password]. This is the name that the `dgruft` user picks
    /// to associated with this [Password]'s data.
    pub fn encrypted_name(&self) -> &Encrypted {
        &self.encrypted_name
    }

    /// Return the encrypted username of this [Password]. This is the username associated with the
    /// stored password itself.
    pub fn encrypted_username(&self) -> &Encrypted {
        &self.encrypted_username
    }

    /// Return the encrypted content of this [Password]. This is the stored password itself.
    pub fn encrypted_content(&self) -> &Encrypted {
        &self.encrypted_content
    }

    /// Return the encrypted notes of this [Password]. These are text notes that the user has
    /// entered that are associated with the password.
    pub fn encrypted_notes(&self) -> &Encrypted {
        &self.encrypted_notes
    }

    /// Decrypt all fields of this [Password], including the secure ones. Use with caution and
    /// restraint!
    pub fn unlock(&self, key: &[u8; 32]) -> Result<DecryptedPasswordFields, Error> {
        Ok(DecryptedPasswordFields {
            name: helpers::bytes_to_utf8(&self.encrypted_name().decrypt(key)?, "password_name")?,
            username: helpers::bytes_to_utf8(
                &self.encrypted_username().decrypt(key)?,
                "password_username",
            )?,
            content: helpers::bytes_to_utf8(
                &self.encrypted_content().decrypt(key)?,
                "password_content",
            )?,
            notes: helpers::bytes_to_utf8(&self.encrypted_notes().decrypt(key)?, "password_notes")?,
        })
    }
}

/// All the decrypted fields of a [Password]. Use with caution and restraint.
pub struct DecryptedPasswordFields {
    name: String,
    username: String,
    content: String,
    notes: String,
}
impl DecryptedPasswordFields {
    /// Return the name of this [DecryptedPasswordFields].
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the username of this [DecryptedPasswordFields].
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Return the content of this [DecryptedPasswordFields].
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Return the notes of this [DecryptedPasswordFields].
    pub fn notes(&self) -> &str {
        &self.notes
    }
}

/// A [Password] converted for base-64 storage.
#[derive(Debug)]
pub struct Base64Password {
    /// Password owner username in base-64 format.
    pub b64_owner_username: String,
    /// Password name ciphertext in base-64 format.
    pub b64_name_ciphertext: String,
    /// Password username ciphertext in base-64 format.
    pub b64_username_ciphertext: String,
    /// Password content ciphertext in base-64 format.
    pub b64_content_ciphertext: String,
    /// Password notes ciphertext in base-64 format.
    pub b64_notes_ciphertext: String,
    /// Password name nonce in base-64 format.
    pub b64_name_nonce: String,
    /// Password username nonce in base-64 format.
    pub b64_username_nonce: String,
    /// Password content nonce in base-64 format.
    pub b64_content_nonce: String,
    /// Password notes nonce in base-64 format.
    pub b64_notes_nonce: String,
}
impl Base64Password {
    /// Output fields as tuple.
    pub fn as_tuple(&self) -> (&str, &str, &str, &str, &str, &str, &str, &str, &str) {
        (
            &self.b64_owner_username,
            &self.b64_name_ciphertext,
            &self.b64_username_ciphertext,
            &self.b64_content_ciphertext,
            &self.b64_notes_ciphertext,
            &self.b64_name_nonce,
            &self.b64_username_nonce,
            &self.b64_content_nonce,
            &self.b64_notes_nonce,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::account::Account;
    use pretty_assertions::assert_eq;

    const TEST_NAME: &str = "Schploggy Login Info";
    const TEST_USERNAME: &str = "my_schploggy_account";
    const TEST_CONTENT: &str = "ILoveSchploggy!123";
    const TEST_NOTES: &str = "Security Question: My father's middle name is Bob.";

    #[test]
    fn test_new_password() {
        let my_account = Account::new("my_account", "my_password").unwrap();
        let my_fields = my_account.unlock("my_password").unwrap();

        let my_password = Password::new(
            my_fields.username(),
            my_fields.key(),
            TEST_NAME,
            TEST_USERNAME,
            TEST_CONTENT,
            TEST_NOTES,
        )
        .unwrap();

        assert_eq!(my_fields.username(), my_password.owner_username());
        assert_eq!(
            TEST_NAME.as_bytes(),
            &my_password
                .encrypted_name()
                .decrypt(my_fields.key())
                .unwrap()[..]
        );
        assert_eq!(
            TEST_USERNAME.as_bytes(),
            &my_password
                .encrypted_username()
                .decrypt(my_fields.key())
                .unwrap()[..]
        );
        assert_eq!(
            TEST_CONTENT.as_bytes(),
            &my_password
                .encrypted_content()
                .decrypt(my_fields.key())
                .unwrap()[..]
        );
        assert_eq!(
            TEST_NOTES.as_bytes(),
            &my_password
                .encrypted_notes()
                .decrypt(my_fields.key())
                .unwrap()[..]
        );
    }

    #[test]
    fn test_to_from_b64() {
        let my_key = crate::backend::encrypted::new_key(None);
        let my_password = Password::new(
            "my_username",
            &my_key,
            TEST_NAME,
            TEST_USERNAME,
            TEST_CONTENT,
            TEST_NOTES,
        )
        .unwrap();

        let my_password_b64 = my_password.to_b64();
        assert_eq!(
            my_password_b64.b64_owner_username,
            helpers::bytes_to_b64("my_username".as_bytes())
        );

        let my_password_from_b64 = Password::from_b64(my_password_b64).unwrap();
        assert_eq!(
            my_password_from_b64
                .encrypted_name()
                .decrypt(&my_key)
                .unwrap(),
            TEST_NAME.as_bytes()
        );
        assert_eq!(
            my_password_from_b64
                .encrypted_username()
                .decrypt(&my_key)
                .unwrap(),
            TEST_USERNAME.as_bytes()
        );
        assert_eq!(
            my_password_from_b64
                .encrypted_content()
                .decrypt(&my_key)
                .unwrap(),
            TEST_CONTENT.as_bytes()
        );
        assert_eq!(
            my_password_from_b64
                .encrypted_notes()
                .decrypt(&my_key)
                .unwrap(),
            TEST_NOTES.as_bytes()
        );
    }
}
