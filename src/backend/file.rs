//! Functionality related to reading and writing encrypted files.
use std::{
    ffi::OsStr,
    fmt::Display,
    fs::{File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    backend::{account::Account, encrypted::Encrypted},
    error::Error,
    helpers,
};

/// Metadata for an encrypted file accessible through `dgruft`.
#[derive(Debug)]
pub struct FileData {
    encrypted_path: Encrypted,
    owner_username: String,
    content_nonce: [u8; 12],
}
impl FileData {
    /// Create a new empty [FileData].
    /// Non-UTF-8 filesystem encodings are unsupported.
    pub fn new<P>(account: &Account, password: &str, path: P) -> Result<Self, Error>
    where
        P: AsRef<Path> + Display,
    {
        Self::new_with_content(account, password, b"", path)
    }

    /// Create a new [FileData] using the given content.
    /// Non-UTF-8 filesystem encodings are unsupported.
    pub fn new_with_content<P>(
        account: &Account,
        password: &str,
        content: &[u8],
        path: P,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path> + Display,
    {
        // Get encryption key.
        let key = *account.unlock(password)?.key();

        // Reject non-UTF-8-encodable paths.
        // WARNING: May not work on Windows at all.
        let path_str = match path.as_ref().to_str() {
            Some(path_str) => path_str,
            None => return Err(Error::NonUtf8FilePathError("new_file_data_path".to_owned())),
        };

        // Create file, handle file creation errors
        let content_nonce = match File::create_new(&path) {
            Ok(_) => Self::encrypt_then_write(&path, content, &key)?,
            Err(err) => match err.kind() {
                ErrorKind::AlreadyExists => {
                    return Err(Error::FileAlreadyExistsError(PathBuf::from(path.as_ref())))
                }
                ErrorKind::NotFound => {
                    return Err(Error::FileNotFoundError(PathBuf::from(path.as_ref())))
                }
                _ => return Err(Error::UnhandledError(err.to_string())),
            },
        };

        let encrypted_path = Encrypted::new(path_str.as_bytes(), &key)?;
        Ok(Self {
            encrypted_path,
            owner_username: account.username().to_owned(),
            content_nonce,
        })
    }

    /// Open, then decrypt, the file at the path defined by this [FileData].
    pub fn open_decrypted(&self, key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let decrypted_path = self.encrypted_path.decrypt(key)?;
        let mut file = Self::open_file(helpers::bytes_to_utf8(&decrypted_path, "decrypted_path")?)?;
        let mut encrypted_bytes: Vec<u8> = vec![];
        if let Err(err) = file.read_to_end(&mut encrypted_bytes) {
            match err.kind() {
                ErrorKind::PermissionDenied => {
                    return Err(Error::PermissionDeniedError(PathBuf::from(
                        helpers::bytes_to_utf8(&decrypted_path, "decrypted_path")?,
                    )));
                }
                _ => return Err(Error::UnhandledError(err.to_string())),
            }
        }
        let encrypted_content = Encrypted::from_bytes(&encrypted_bytes, &self.content_nonce);
        encrypted_content.decrypt(key)
    }

    // Helper function to open file.
    fn open_file<P>(path: P) -> Result<File, Error>
    where
        P: AsRef<Path> + Display,
    {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(path.as_ref())
        {
            Ok(file) => Ok(file),
            Err(err) => match err.kind() {
                ErrorKind::NotFound => Err(Error::FileNotFoundError(PathBuf::from(path.as_ref()))),
                ErrorKind::PermissionDenied => {
                    Err(Error::PermissionDeniedError(PathBuf::from(path.as_ref())))
                }
                _ => Err(Error::UnhandledError(err.to_string())),
            },
        }
    }

    // Helper function to write content to file. Returns nonce used to encrypt text.
    fn encrypt_then_write<P>(path: P, content: &[u8], key: &[u8; 32]) -> Result<[u8; 12], Error>
    where
        P: AsRef<Path> + Display,
    {
        let encrypted_content = Encrypted::new(content, key)?;
        let mut file = Self::open_file(&path)?;
        if let Err(err) = file.write_all(encrypted_content.ciphertext()) {
            match err.kind() {
                ErrorKind::NotFound => {
                    return Err(Error::FileNotFoundError(PathBuf::from(path.as_ref())))
                }
                ErrorKind::PermissionDenied => {
                    return Err(Error::PermissionDeniedError(PathBuf::from(path.as_ref())))
                }
                _ => return Err(Error::UnhandledError(err.to_string())),
            }
        }
        Ok(*encrypted_content.nonce())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::account::Account;

    const TEST_USERNAME: &str = "my_account";
    const TEST_PASSWORD: &str = "my_password";
    const TEST_CONTENT: &str = "
        My secret Christmas gift list:
        Bobby: Football
        Alice: аукцыон
        Charlie: 棋盘游戏

        Don't tell anybody!!!!
        ";

    // TODO: save file, write to file, encrypt, decrypt, read file
    #[test]
    fn test_file_read_write() {
        let my_account = Account::new(TEST_USERNAME, TEST_PASSWORD).unwrap();
        let unlocked = my_account.unlock(TEST_PASSWORD).unwrap();
        let my_file = FileData::new_with_content(
            &my_account,
            TEST_PASSWORD,
            TEST_CONTENT.as_bytes(),
            "test_files/testfile",
        )
        .unwrap();
        let content = my_file.open_decrypted(unlocked.key()).unwrap();
        assert_eq!(TEST_CONTENT.as_bytes(), content);
        assert_eq!(
            TEST_CONTENT,
            helpers::bytes_to_utf8(&content, "test_content").unwrap()
        );
    }
}
