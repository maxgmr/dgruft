use std::fmt;

use crate::backend::{
    hashed::{HashFn, Hashed},
    salt::Salt,
};

#[derive(Debug)]
/// Different ways in which the arguments to [Account::new] can be invalid.
pub enum AccountCreationError {
    /// The username is too long. usize = max length.
    UsernameTooLong(usize),
    /// The username is too short. usize = min length.
    UsernameTooShort(usize),
    /// The password is too long. usize = max length.
    PasswordTooLong(usize),
    /// The password is too short. usize = min length.
    PasswordTooShort(usize),
    /// There are invalid chars in the username. char = invalid char.
    InvalidUsernameChars(char),
    /// There are invalid chars in the password. char = invalid char.
    InvalidPasswordChars(char),
    /// There was an error when calling [Hashed::new]. String = the error.
    PasswordHashingError(String),
}
impl fmt::Display for AccountCreationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            AccountCreationError::UsernameTooLong(max_len) => {
                format!("Username must be {} characters or less.", max_len)
            }
            AccountCreationError::UsernameTooShort(min_len) => {
                format!("Username must be at least {} characters.", min_len)
            }
            AccountCreationError::PasswordTooLong(max_len) => {
                format!("Password must be {} characters or less.", max_len)
            }
            AccountCreationError::PasswordTooShort(min_len) => {
                format!("Password must be at least {} characters.", min_len)
            }
            AccountCreationError::InvalidUsernameChars(forbidden_char) => {
                format!(
                    "Usernames cannot contain this character: '{}'",
                    forbidden_char
                )
            }
            AccountCreationError::InvalidPasswordChars(forbidden_char) => {
                format!(
                    "Passwords cannot contain this character: '{}'",
                    forbidden_char
                )
            }
            AccountCreationError::PasswordHashingError(message) => message.to_owned(),
        };
        write!(f, "{}", message)
    }
}
impl std::error::Error for AccountCreationError {}

/// The restrictions placed on this particular account.
pub struct Restrictions {
    /// The minimum allowed length of the username.
    pub username_min_length: usize,
    /// The maximum allowed length of the username.
    pub username_max_length: usize,
    /// The minimum allowed length of the password.
    pub password_min_length: usize,
    /// The maximum allowed length of the password.
    pub password_max_length: usize,
    /// The characters allowed in the username.
    pub allowed_username_characters: String,
    /// The characters allowed in the password.
    pub allowed_password_characters: String,
}

#[derive(Debug)]
/// An account with a username and hashed password. Also shows the salt and hash function used to
/// encrypt the password.
pub struct Account {
    username: String,
    password: Hashed,
    hash_fn: HashFn,
    salt: Salt,
}

impl Account {
    /// Create a new [Account] from a given username and password. Returns [AccountCreationError] if [Restrictions]
    /// are not met.
    pub fn new(
        username: String,
        password: String,
        restrictions: Restrictions,
        hash_fn: HashFn,
        salt_size: usize,
    ) -> Result<Self, AccountCreationError> {
        // Check username & password against restrictions
        if username.len() < restrictions.username_min_length {
            return Err(AccountCreationError::UsernameTooShort(
                restrictions.username_min_length,
            ));
        }
        if username.len() > restrictions.username_max_length {
            return Err(AccountCreationError::UsernameTooLong(
                restrictions.username_max_length,
            ));
        }
        if password.len() < restrictions.password_min_length {
            return Err(AccountCreationError::PasswordTooShort(
                restrictions.password_min_length,
            ));
        }
        if password.len() > restrictions.password_max_length {
            return Err(AccountCreationError::PasswordTooLong(
                restrictions.password_max_length,
            ));
        }
        for c in username.chars() {
            if !restrictions.allowed_username_characters.contains(c) {
                return Err(AccountCreationError::InvalidUsernameChars(c));
            }
        }
        for c in password.chars() {
            if !restrictions.allowed_password_characters.contains(c) {
                return Err(AccountCreationError::InvalidPasswordChars(c));
            }
        }

        // Params OK
        let salt = Salt::new(salt_size);
        let password_hashed_salted = match Hashed::new(&password, hash_fn, Some(&salt)) {
            Ok(p_h_s) => p_h_s,
            Err(e) => {
                return Err(AccountCreationError::PasswordHashingError(format!(
                    "{:?}",
                    e.get_ref()
                )));
            }
        };

        Ok(Self {
            username,
            password: password_hashed_salted,
            hash_fn,
            salt,
        })
    }

    /// Get this account's username.
    pub fn get_username(&self) -> &str {
        &self.username
    }

    /// Get this account's [Hashed] password.
    pub fn get_password(&self) -> &Hashed {
        &self.password
    }

    /// Get the [HashFn] used to encrypt this account's password.
    pub fn get_hash_fn(&self) -> &HashFn {
        &self.hash_fn
    }

    /// Get the [Salt] used to encrypt this account's password.
    pub fn get_salt(&self) -> &Salt {
        &self.salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const USERNAME_ALLOW: &str =
        "#-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~";
    const PASSWORD_ALLOW: &str = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

    fn get_test_restrictions() -> Restrictions {
        Restrictions {
            username_min_length: 3,
            username_max_length: 32,
            password_min_length: 8,
            password_max_length: 512,
            allowed_username_characters: USERNAME_ALLOW.to_owned(),
            allowed_password_characters: PASSWORD_ALLOW.to_owned(),
        }
    }

    #[test]
    fn test_acc_ok() {
        Account::new(
            "account".to_owned(),
            "password123".to_owned(),
            get_test_restrictions(),
            HashFn::Sha256,
            16,
        )
        .unwrap();
    }

    #[test]
    fn test_acc_user_too_long() {
        let err = Account::new(
            String::from("kjsfhalgkjhglksajhgkdjhgalkdsjghaslgkjhkehakhgeghskjgh"),
            String::from("my password"),
            get_test_restrictions(),
            HashFn::Sha256,
            16,
        )
        .unwrap_err();
        if let AccountCreationError::UsernameTooLong(max_len) = err {
            assert_eq!(get_test_restrictions().username_max_length, max_len);
        } else {
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_acc_pass_too_short() {
        let err = Account::new(
            String::from("my_account_123"),
            String::from("heheheh"),
            get_test_restrictions(),
            HashFn::Sha256,
            16,
        )
        .unwrap_err();
        if let AccountCreationError::PasswordTooShort(min_len) = err {
            assert_eq!(get_test_restrictions().password_min_length, min_len);
        } else {
            dbg!(&err);
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_acc_invalid_user_chars() {
        let err = Account::new(
            String::from("my_account&_123"),
            String::from("hehehehe"),
            get_test_restrictions(),
            HashFn::Sha256,
            16,
        )
        .unwrap_err();
        if let AccountCreationError::InvalidUsernameChars(char) = err {
            assert_eq!('&', char);
        } else {
            dbg!(&err);
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_acc_invalid_pass_chars() {
        let err = Account::new(
            String::from("my_account_123"),
            String::from("пассворд"),
            get_test_restrictions(),
            HashFn::Sha256,
            16,
        )
        .unwrap_err();
        if let AccountCreationError::InvalidPasswordChars(char) = err {
            assert_eq!('п', char);
        } else {
            dbg!(&err);
            panic!("Wrong error type");
        }
    }
}
