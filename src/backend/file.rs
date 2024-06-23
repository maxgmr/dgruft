//! Functionality related to reading and writing encrypted files.
use std::{
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
        P: AsRef<Path>,
    {
        Self::new_with_content(account, password, b"", path)
    }

    /// Create a new empty [FileData] with a key.
    /// Non-UTF-8 filesystem encodings are unsupported.
    pub fn new_with_key<P>(username: &str, key: &[u8; 32], path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Self::new_with_content_and_key(username, key, b"", path)
    }

    /// Create a new [FileData] using the given content and key.
    /// Non-UTF-8 filesystem encodings are unsupported.
    pub fn new_with_content_and_key<P>(
        username: &str,
        key: &[u8; 32],
        content: &[u8],
        path: P,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        // Reject non-UTF-8-encodable paths.
        // WARNING: May not work on Windows at all.
        let path_str = match path.as_ref().to_str() {
            Some(path_str) => path_str,
            None => return Err(Error::NonUtf8FilePathError("new_file_data_path".to_owned())),
        };

        // Create file, handle file creation errors
        let content_nonce = match File::create_new(&path) {
            Ok(_) => Self::encrypt_then_write(&path, content, key)?,
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

        let encrypted_path = Encrypted::new(path_str.as_bytes(), key)?;
        Ok(Self {
            encrypted_path,
            owner_username: username.to_owned(),
            content_nonce,
        })
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
        P: AsRef<Path>,
    {
        // Get encryption key.
        let key = *account.unlock(password)?.key();
        Self::new_with_content_and_key(account.username(), &key, content, path)
    }

    /// Decrypt then edit the file pointed to by this [FileData] in the computer's default text editor. The file
    /// is then re-encrypted and saved after editing.
    pub fn edit(&mut self, key: &[u8; 32]) -> Result<(), Error> {
        let decrypted_bytes = self.open_decrypted(key)?;
        // let decrypted_string = helpers::bytes_to_utf8(&decrypted_bytes, "edit_file")?;
        let decrypted_path_bytes = self.encrypted_path.decrypt(key)?;
        let decrypted_path_buf = PathBuf::from(helpers::bytes_to_utf8(
            &decrypted_path_bytes,
            "decrypted_path",
        )?);

        let edited_bytes = match edit::edit_bytes(decrypted_bytes) {
            Ok(bytes) => bytes,
            Err(err) => match err.kind() {
                ErrorKind::InvalidData => {
                    return Err(Error::Utf8FromBytesError("edit_file".to_owned()));
                }
                ErrorKind::NotFound => {
                    return Err(Error::FileNotFoundError(decrypted_path_buf.clone()));
                }
                _ => return Err(Error::UnhandledError(err.to_string())),
            },
        };

        let content_nonce = Self::encrypt_then_write(decrypted_path_buf, &edited_bytes, key)?;

        self.content_nonce = content_nonce;

        Ok(())
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

    /// Load [FileData] from [Base64FileData]— a set of base-64-encoded strings.
    pub fn from_b64(b64_file_data: Base64FileData) -> Result<Self, Error> {
        let encrypted_path = Encrypted::from_b64(
            &b64_file_data.b64_encrypted_path,
            &b64_file_data.b64_path_nonce,
        )?;
        let owner_username = helpers::bytes_to_utf8(
            &helpers::b64_to_bytes(&b64_file_data.b64_owner_username)?,
            "owner_username",
        )?;
        let content_nonce: [u8; 12] =
            helpers::b64_to_fixed(b64_file_data.b64_content_nonce, "content_nonce")?;

        Ok(Self {
            encrypted_path,
            owner_username,
            content_nonce,
        })
    }

    /// Convert this [FileData] to a [Base64FileData] for storage.
    pub fn to_b64(&self) -> Base64FileData {
        Base64FileData {
            b64_encrypted_path: self.encrypted_path().ciphertext_as_b64(),
            b64_path_nonce: self.encrypted_path().nonce_as_b64(),
            b64_owner_username: helpers::bytes_to_b64(self.owner_username().as_bytes()),
            b64_content_nonce: helpers::bytes_to_b64(self.content_nonce()),
        }
    }

    // Helper function to open file.
    fn open_file<P>(path: P) -> Result<File, Error>
    where
        P: AsRef<Path>,
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
        P: AsRef<Path>,
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

    // GETTERS

    /// Return the encrypted path of this [FileData].
    pub fn encrypted_path(&self) -> &Encrypted {
        &self.encrypted_path
    }

    /// Return the owner username of this [FileData].
    pub fn owner_username(&self) -> &str {
        &self.owner_username
    }

    /// Return the nonce used to encrypt the content of this [FileData].
    pub fn content_nonce(&self) -> &[u8; 12] {
        &self.content_nonce
    }
}

/// [FileData] converted for base-64 storage.
#[derive(Debug)]
pub struct Base64FileData {
    /// Encrypted path in base-64 format.
    pub b64_encrypted_path: String,
    /// Encrypted path nonce in base-64 format.
    pub b64_path_nonce: String,
    /// Owner username in base-64 format.
    pub b64_owner_username: String,
    /// Encrypted content nonce in base-64 format.
    pub b64_content_nonce: String,
}
impl Base64FileData {
    /// Output fields as tuple.
    pub fn as_tuple(&self) -> (&str, &str, &str, &str) {
        (
            &self.b64_encrypted_path,
            &self.b64_path_nonce,
            &self.b64_owner_username,
            &self.b64_content_nonce,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::account::Account;
    use pretty_assertions::assert_eq;
    use std::process::Command;

    const TEST_USERNAME: &str = "my_account";
    const TEST_PASSWORD: &str = "my_password";
    const TEST_CONTENT: &str = "My secret Christmas gift list:
Bobby: Football
Alice: аукцыон
Charlie: 棋盘游戏

Don't tell anybody!!!!";

    fn cleanup_test_file(path: &str) {
        Command::new("rm").arg(path).status().expect("failed");
    }

    #[test]
    fn test_file_read_write() {
        let test_file = "test_files/testfile1";
        let my_account = Account::new(TEST_USERNAME, TEST_PASSWORD).unwrap();
        let unlocked = my_account.unlock(TEST_PASSWORD).unwrap();
        let my_file = FileData::new_with_content(
            &my_account,
            TEST_PASSWORD,
            TEST_CONTENT.as_bytes(),
            test_file,
        )
        .unwrap();
        let content = my_file.open_decrypted(unlocked.key()).unwrap();
        assert_eq!(TEST_CONTENT.as_bytes(), content);
        assert_eq!(
            TEST_CONTENT,
            helpers::bytes_to_utf8(&content, "test_content").unwrap()
        );
        cleanup_test_file(test_file);
    }

    #[test]
    #[ignore] // run using `cargo t -- --ignored --nocapture`
    fn test_file_edit() {
        // Must be manually verified
        let test_file = "test_files/my_test_file";
        let my_account = Account::new(TEST_USERNAME, TEST_PASSWORD).unwrap();
        let unlocked = my_account.unlock(TEST_PASSWORD).unwrap();
        let mut my_file = FileData::new_with_content(
            &my_account,
            TEST_PASSWORD,
            TEST_CONTENT.as_bytes(),
            test_file,
        )
        .unwrap();
        my_file.edit(unlocked.key()).unwrap();
        let content = my_file.open_decrypted(unlocked.key()).unwrap();
        println!("{}", helpers::bytes_to_utf8(&content, "content").unwrap());

        cleanup_test_file(test_file);
    }

    #[test]
    fn test_to_from_b64() {
        let test_file = "test_files/testfile2";
        let my_account = Account::new(TEST_USERNAME, TEST_PASSWORD).unwrap();
        let unlocked = my_account.unlock(TEST_PASSWORD).unwrap();
        let my_file = FileData::new_with_content(
            &my_account,
            TEST_PASSWORD,
            TEST_CONTENT.as_bytes(),
            test_file,
        )
        .unwrap();

        let my_b64_file = my_file.to_b64();
        let my_loaded_file = FileData::from_b64(my_b64_file).unwrap();

        let content = my_loaded_file.open_decrypted(unlocked.key()).unwrap();
        assert_eq!(TEST_CONTENT.as_bytes(), content);
        assert_eq!(
            TEST_CONTENT,
            helpers::bytes_to_utf8(&content, "test_content").unwrap()
        );
        cleanup_test_file(test_file);
    }

    #[test]
    fn test_already_exists() {
        let test_file = "test_files/testfile3";
        let my_account = Account::new(TEST_USERNAME, TEST_PASSWORD).unwrap();
        let other_account = Account::new("123", "456").unwrap();
        FileData::new(&my_account, TEST_PASSWORD, test_file).unwrap();
        let dupe = FileData::new(&other_account, "456", test_file).unwrap_err();

        if let Error::FileAlreadyExistsError(_) = dupe {
        } else {
            panic!("Wrong error type");
        }
        cleanup_test_file(test_file);
    }

    #[test]
    fn test_another_account_open() {
        let test_file = "test_files/testfile4";
        let my_account = Account::new(TEST_USERNAME, TEST_PASSWORD).unwrap();
        let other_account = Account::new("123", "456").unwrap();
        let other_unlocked = other_account.unlock("456").unwrap();
        let my_file = FileData::new_with_content(
            &my_account,
            TEST_PASSWORD,
            TEST_CONTENT.as_bytes(),
            test_file,
        )
        .unwrap();
        my_file.open_decrypted(other_unlocked.key()).unwrap_err();
        cleanup_test_file(test_file);
    }
}
