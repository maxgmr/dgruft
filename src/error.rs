//! All the different backend errors that dgruft can experience, meant to be displayed in the
//! frontend.
use core::fmt;
use std::path::PathBuf;

/// A list of all the handled dgruft errors.
#[derive(Clone, Debug)]
pub enum Error {
    /// Given password was incorrect.
    IncorrectPasswordError,
    /// Invalid encoding of provided base 64 string.
    InvalidB64Error(String),
    /// Tried to read incorrect-length base 64 string.
    InvalidLengthB64Error(String, usize, usize),
    /// Failed to convert to base 64.
    ToB64Error(String),
    /// Could not parse UTF-8 string from bytes.
    Utf8FromBytesError(String),
    /// Could not find an account with that username in database.
    AccountNotFoundError(String),
    /// Problem encrypting something.
    EncryptionError(String),
    /// Problem decrypting something.
    DecryptionError(String),
    /// Tried to create file at a path that already exists.
    FileAlreadyExistsError(PathBuf),
    /// Tried to interact with a file with insufficient permissions.
    PermissionDeniedError(PathBuf),
    /// Tried to open a file that doesn't exist.
    FileNotFoundError(PathBuf),
    /// Tried to use non-UTF-8 file path.
    NonUtf8FilePathError(String),
    /// Generic error thrown when there is no [Error] enum value. Should only be used for errors
    /// that should never occur.
    UnhandledError(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = match self {
            Error::IncorrectPasswordError => String::from("IncorrectPasswordError"),
            Error::InvalidB64Error(input_string) => {
                format!(
                    "InvalidB64Error: String \"{}\" is not a valid base-64 string.",
                    input_string
                )
            }
            Error::InvalidLengthB64Error(var_name, intended_length, actual_length) => {
                format!(
                    "InvalidLengthError: Tried to read {} bytes into {} bytes of {}.",
                    actual_length, intended_length, var_name
                )
            }
            Error::ToB64Error(var_name) => {
                format!("ToB64Error: Failed to convert \"{var_name}\" to base-64.")
            }
            Error::Utf8FromBytesError(var_name) => {
                format!(
                    "Utf8FromBytesError: Could not parse byte sequence \"{}\" as a valid UTF-8 string.", var_name
                )
            }
            Error::AccountNotFoundError(username) => {
                format!(
                    "AccountNotFoundError: Account \"{username}\" does not exist in the database."
                )
            }
            Error::EncryptionError(error_as_string) => {
                format!("EncryptionError: {}", error_as_string)
            }
            Error::DecryptionError(error_as_string) => {
                format!("DecryptionError: {}", error_as_string)
            }
            Error::FileNotFoundError(path) => {
                format!(
                    "FileNotFoundError: File at \"{}\" does not exist.",
                    path.display()
                )
            }
            Error::FileAlreadyExistsError(path) => {
                format!("FileAlreadyExistsError: Cannot create new file at \"{}\"— file already exists.", path.display())
            }
            Error::PermissionDeniedError(path) => {
                format!(
                    "PermissionDeniedError: Permission denied for path \"{}\".",
                    path.display()
                )
            }
            Error::NonUtf8FilePathError(var_name) => {
                format!(
                    "NonUtf8FilePathError: The path for \"{}\" is not UTF-8 encoded.",
                    var_name
                )
            }
            Error::UnhandledError(error_as_string) => {
                format!("UnhandledError: {}", error_as_string)
            }
        };
        write!(f, "{}", message)
    }
}
impl std::error::Error for Error {}
