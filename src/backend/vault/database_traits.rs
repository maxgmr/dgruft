//! These traits determine how different types can be converted into types accepted by the `dgruft`
//! database.

use base64ct::{Base64, Encoding};
use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre;

use super::super::{account::Account, credential::Credential, file_data::FileData};

/// This trait defines how the given struct gets converted into an array of base-64-encoded strings
/// for storage in the database.
pub trait IntoDatabase {
    type FixedSizeStringArray;

    /// This function determines how the struct gets converted into the database format.
    fn into_database(self) -> Self::FixedSizeStringArray;
}

// Implementations
impl IntoDatabase for Account {
    type FixedSizeStringArray = [String; 6];
    fn into_database(self) -> Self::FixedSizeStringArray {
        [
            into_b64(self.username()),
            into_b64(self.password_salt()),
            into_b64(self.dbl_hashed_password().hash()),
            into_b64(self.dbl_hashed_password().salt()),
            into_b64(self.encrypted_key().cipherbytes()),
            into_b64(self.encrypted_key().nonce()),
        ]
    }
}
impl IntoDatabase for Credential {
    type FixedSizeStringArray = [String; 9];
    fn into_database(self) -> Self::FixedSizeStringArray {
        [
            into_b64(self.owner_username()),
            into_b64(self.encrypted_name().cipherbytes()),
            into_b64(self.encrypted_name().nonce()),
            into_b64(self.encrypted_username().cipherbytes()),
            into_b64(self.encrypted_username().nonce()),
            into_b64(self.encrypted_password().cipherbytes()),
            into_b64(self.encrypted_password().nonce()),
            into_b64(self.encrypted_notes().cipherbytes()),
            into_b64(self.encrypted_notes().nonce()),
        ]
    }
}
impl IntoDatabase for FileData {
    type FixedSizeStringArray = [String; 4];
    fn into_database(self) -> Self::FixedSizeStringArray {
        [
            into_b64_camino(self.path()),
            into_b64(self.filename()),
            into_b64(self.owner_username()),
            into_b64(self.contents_nonce()),
        ]
    }
}

/// This trait defines how the given struct gets converted from a vector of base-64-encoded strings
/// for retrieval from the database.
pub trait TryFromDatabase {
    const expected_size: usize;

    /// This function determines how the struct gets converted into the database format.
    fn try_from_database(b64_vec: Vec<String>) -> eyre::Result<Self>
    where
        Self: Sized;
}

// Implementations
// impl TryFromDatabase for Account {
//
// }

// Helper function to convert camino structs to b64.
fn into_b64_camino<T>(input: T) -> String
where
    T: AsRef<Utf8Path>,
{
    Base64::encode_string(input.as_ref().as_str().as_bytes())
}

// Helper function to convert things to b64.
fn into_b64<T>(input: T) -> String
where
    T: Into<Vec<u8>>,
{
    let bytes_vec: Vec<u8> = input.into();
    Base64::encode_string(&bytes_vec)
}

// Helper function to convert b64 strings to UTF-8 path buffers.
fn b64_to_utf8_path(input: &str) -> eyre::Result<Utf8PathBuf> {
    Ok(Utf8PathBuf::from(b64_to_utf8(input)?))
}

// Helper function to convert b64 strings to UTF-8 strings.
fn b64_to_utf8(input: &str) -> eyre::Result<String> {
    Ok(String::from_utf8(b64_to_bytes(input)?)?)
}

// Helper function to convert b64 strings to vectors of bytes.
fn b64_to_bytes(input: &str) -> eyre::Result<Vec<u8>> {
    Ok(Base64::decode_vec(input)?)
}
