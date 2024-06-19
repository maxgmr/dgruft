//! Functionality for individual dgruft user accounts.
use crate::backend::{encrypted, encrypted::Encrypted, hashed::Hashed};
use crate::error::Error;
use crate::helpers;

/// An account with a username, password, and encryption key.
#[derive(Debug)]
pub struct Account {
    username: String,
    password_salt: [u8; 64],
    dbl_hashed_password: Hashed,
    encrypted_key: Encrypted,
}
impl Account {
    /// Create a new [Account] from a username and a password.
    pub fn new(username: &str, password: &str) -> Result<Self, Error> {
        // Generate a random AES-256 encryption key
        let key = encrypted::new_key(None);
        // Hash the password
        let hashed_password = Hashed::new(password.as_bytes());
        // Use the hashed password as the key to encrypt the encryption key
        let encrypted_key = Encrypted::new(&key, hashed_password.hash())?;
        // Hash the password again to store it
        let dbl_hashed_password = Hashed::new(hashed_password.hash());
        Ok(Self {
            username: username.to_string(),
            password_salt: *hashed_password.salt(),
            dbl_hashed_password,
            encrypted_key,
        })
    }

    /// Load an [Account] from a [Base64Account]— a set of base-64-encoded strings.
    pub fn from_b64(b64_account: Base64Account) -> Result<Self, Error> {
        let username = helpers::bytes_to_utf8(
            &helpers::b64_to_bytes(&b64_account.b64_username)?,
            "username",
        )?;
        let password_salt: [u8; 64] =
            helpers::b64_to_fixed(b64_account.b64_password_salt, "b64_password_salt")?;
        let dbl_hashed_password = Hashed::from_b64(
            &b64_account.b64_dbl_hashed_password_hash,
            &b64_account.b64_dbl_hashed_password_salt,
        )?;
        let encrypted_key = Encrypted::from_b64(
            &b64_account.b64_encrypted_key_ciphertext,
            &b64_account.b64_encrypted_key_nonce,
        )?;

        Ok(Self {
            username,
            password_salt,
            dbl_hashed_password,
            encrypted_key,
        })
    }

    /// Convert this [Account] to a [Base64Account] for storage.
    pub fn to_b64(&self) -> Base64Account {
        Base64Account {
            b64_username: helpers::bytes_to_b64(self.username().as_bytes()),
            b64_password_salt: helpers::bytes_to_b64(self.password_salt()),
            b64_dbl_hashed_password_hash: self.dbl_hashed_password().hash_as_b64(),
            b64_dbl_hashed_password_salt: self.dbl_hashed_password().salt_as_b64(),
            b64_encrypted_key_ciphertext: self.encrypted_key().ciphertext_as_b64(),
            b64_encrypted_key_nonce: self.encrypted_key().nonce_as_b64(),
        }
    }

    /// Return true iff the entered password matches the password stored in this [Account].
    pub fn check_password_match(&self, password: &str) -> bool {
        let hashed_password = Hashed::from_salt(password.as_bytes(), self.password_salt());
        let dbl_hashed_password =
            Hashed::from_salt(hashed_password.hash(), self.dbl_hashed_password.salt());
        self.dbl_hashed_password.hash() == dbl_hashed_password.hash()
    }

    // GETTERS

    /// Return the username of this [Account].
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Return the password salt of this [Account].
    pub fn password_salt(&self) -> &[u8; 64] {
        &self.password_salt
    }

    /// Return the double-hashed password of this [Account].
    pub fn dbl_hashed_password(&self) -> &Hashed {
        &self.dbl_hashed_password
    }

    /// Return the encrypted key of this [Account].
    pub fn encrypted_key(&self) -> &Encrypted {
        &self.encrypted_key
    }

    /// Get all fields of this [Account], including the secure ones. Use with caution and
    /// restraint!
    pub fn unlock(&self, password: &str) -> Result<SecureFields, Error> {
        let hashed_password = Hashed::from_salt(password.as_bytes(), self.password_salt());
        let dbl_hashed_password =
            Hashed::from_salt(hashed_password.hash(), self.dbl_hashed_password.salt());

        // Check if password matches
        if dbl_hashed_password.hash() != self.dbl_hashed_password.hash() {
            Err(Error::IncorrectPasswordError)
        } else {
            // Password OK, continue collecting fields
            let key: [u8; 32] = self
                .encrypted_key()
                .decrypt(hashed_password.hash())?
                .try_into()
                .unwrap();

            Ok(SecureFields {
                username: self.username().to_owned(),
                password: password.to_owned(),
                hashed_password,
                dbl_hashed_password,
                key,
                encrypted_key: self.encrypted_key().clone(),
            })
        }
    }
}

/// All the fields of an [Account], including the ones only accessible by password. Use with
/// caution and restraint.
#[derive(Debug)]
pub struct SecureFields {
    username: String,
    password: String,
    hashed_password: Hashed,
    dbl_hashed_password: Hashed,
    key: [u8; 32],
    encrypted_key: Encrypted,
}
impl SecureFields {
    /// Return the username of this [SecureFields].
    pub fn username(&self) -> &str {
        &self.username
    }
    /// Return the password of this [SecureFields].
    pub fn password(&self) -> &str {
        &self.password
    }
    /// Return the hashed_password of this [SecureFields].
    pub fn hashed_password(&self) -> &Hashed {
        &self.hashed_password
    }
    /// Return the dbl_hashed_password of this [SecureFields].
    pub fn dbl_hashed_password(&self) -> &Hashed {
        &self.dbl_hashed_password
    }
    /// Return the key of this [SecureFields].
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
    /// Return the encrypted_key of this [SecureFields].
    pub fn encrypted_key(&self) -> &Encrypted {
        &self.encrypted_key
    }
}

/// An [Account] converted for base-64 storage.
#[derive(Debug)]
pub struct Base64Account {
    /// Account username in base-64 format.
    pub b64_username: String,
    /// Account password salt in base-64 format.
    pub b64_password_salt: String,
    /// Account double-hashed password hash in base-64 format.
    pub b64_dbl_hashed_password_hash: String,
    /// Account double-hashed password salt in base-64 format.
    pub b64_dbl_hashed_password_salt: String,
    /// Account encrypted key ciphertext in base-64 format.
    pub b64_encrypted_key_ciphertext: String,
    /// Account encrypted key nonce in base-64 format.
    pub b64_encrypted_key_nonce: String,
}
impl Base64Account {
    /// Output fields as tuple.
    pub fn as_tuple(&self) -> (&str, &str, &str, &str, &str, &str) {
        (
            &self.b64_username,
            &self.b64_password_salt,
            &self.b64_dbl_hashed_password_hash,
            &self.b64_dbl_hashed_password_salt,
            &self.b64_encrypted_key_ciphertext,
            &self.b64_encrypted_key_nonce,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_new_acc() {
        let my_account = Account::new("my_account", "my_password").unwrap();
        assert!(my_account.check_password_match("my_password"));

        let incorrect_attempt = my_account.unlock("not my password").unwrap_err();
        if let Error::IncorrectPasswordError = incorrect_attempt {
        } else {
            dbg!(&incorrect_attempt);
            panic!("Wrong error type");
        }

        let my_fields = my_account.unlock("my_password").unwrap();
        let hashed_password = Hashed::from_salt(b"my_password", my_account.password_salt());
        let dbl_hashed_password = Hashed::from_salt(
            hashed_password.hash(),
            my_account.dbl_hashed_password().salt(),
        );
        let key: [u8; 32] = my_account
            .encrypted_key()
            .decrypt(hashed_password.hash())
            .unwrap()
            .try_into()
            .unwrap();
        let encrypted_key = Encrypted::from_nonce(
            &key,
            hashed_password.hash(),
            my_fields.encrypted_key().nonce(),
        )
        .unwrap();
        assert_eq!("my_account", my_fields.username());
        assert_eq!("my_password", my_fields.password());
        assert_eq!(hashed_password.hash(), my_fields.hashed_password().hash());
        assert_eq!(hashed_password.salt(), my_fields.hashed_password().salt());
        assert_eq!(
            dbl_hashed_password.hash(),
            my_fields.dbl_hashed_password().hash()
        );
        assert_eq!(
            dbl_hashed_password.salt(),
            my_fields.dbl_hashed_password().salt()
        );
        assert_eq!(&key, my_fields.key());
        assert_eq!(
            encrypted_key.ciphertext(),
            my_fields.encrypted_key().ciphertext()
        );
        assert_eq!(encrypted_key.nonce(), my_fields.encrypted_key().nonce());
    }

    #[test]
    fn test_to_from_b64() {
        let my_account = Account::new("马克斯", "secretpassword123").unwrap();
        let hashed_password = Hashed::from_salt(b"secretpassword123", my_account.password_salt());
        let dbl_hashed_password = Hashed::from_salt(
            hashed_password.hash(),
            my_account.dbl_hashed_password().salt(),
        );
        let key = my_account
            .encrypted_key()
            .decrypt(hashed_password.hash())
            .unwrap();
        let encrypted_key = Encrypted::from_nonce(
            &key,
            hashed_password.hash(),
            my_account.encrypted_key().nonce(),
        )
        .unwrap();

        let my_account_b64 = my_account.to_b64();
        assert_eq!("6ams5YWL5pav", my_account_b64.b64_username);
        assert_eq!(
            dbl_hashed_password.hash_as_b64(),
            my_account_b64.b64_dbl_hashed_password_hash
        );
        assert_eq!(
            dbl_hashed_password.salt_as_b64(),
            my_account_b64.b64_dbl_hashed_password_salt
        );
        assert_eq!(
            encrypted_key.ciphertext_as_b64(),
            my_account_b64.b64_encrypted_key_ciphertext
        );
        assert_eq!(
            encrypted_key.nonce_as_b64(),
            my_account_b64.b64_encrypted_key_nonce
        );

        let my_account_2 = Account::from_b64(my_account_b64).unwrap();
        assert_eq!("马克斯", my_account_2.username());
        assert_eq!(
            dbl_hashed_password.hash(),
            my_account_2.dbl_hashed_password().hash()
        );
        assert_eq!(
            dbl_hashed_password.salt(),
            my_account_2.dbl_hashed_password().salt()
        );
        assert_eq!(
            encrypted_key.ciphertext(),
            my_account_2.encrypted_key.ciphertext()
        );
        assert_eq!(encrypted_key.nonce(), my_account_2.encrypted_key.nonce());
    }
}
