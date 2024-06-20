//! All the different backend errors that dgruft can experience, meant to be displayed in the
//! frontend.
use core::fmt;

/// A list of all the handled dgruft errors.
#[derive(Clone, Debug)]
pub enum Error {
    /// Given password was incorrect.
    IncorrectPasswordError,
    /// Invalid encoding of provided base 64 string.
    InvalidB64Error(String),
    /// Tried to read incorrect-length base 64 string.
    InvalidLengthB64Error(String, usize, usize),
    /// Could not parse UTF-8 string from bytes.
    Utf8FromBytesError(String),
    /// Problem encrypting something.
    EncryptionError(String),
    /// Problem decrypting something.
    DecryptionError(String),
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
            Error::Utf8FromBytesError(var_name) => {
                format!(
                    "Utf8FromBytesError: Could not parse byte sequence \"{}\" as a valid UTF-8 string.", var_name
                )
            }
            Error::EncryptionError(error_as_string) => {
                format!("EncryptionError: {}", error_as_string)
            }
            Error::DecryptionError(error_as_string) => {
                format!("DecryptionError: {}", error_as_string)
            }
            Error::UnhandledError(error_as_string) => {
                format!("UnhandledError: {}", error_as_string)
            }
        };
        write!(f, "{}", message)
    }
}