//! These traits determine how different types can be converted into types accepted by the `dgruft`
//! database.

use base64ct::{Base64, Encoding};
use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{self, eyre};

use super::{
    super::{
        account::Account,
        credential::Credential,
        encryption::encrypted::{Aes256Key, Aes256Nonce, Encrypted},
        file_data::FileData,
        hashing::hashed::{Hash, Hashed, Salt},
    },
    sql_statements::*,
};

/// Implementors of this trait have a set of basic, core SQLite statements.
pub trait HasSqlStatements {
    /// This enum defines the names of the fields that can be updated.
    type UpdateField;
    /// This function defines the SQLite statement used to insert an entry of this type.
    fn sql_insert() -> &'static str;

    /// This function defines the SQLite statement used to delete an entry of this type.
    fn sql_delete() -> &'static str;

    /// This function defines the SQLite statement used to select an entry of this type.
    fn sql_select() -> &'static str;

    /// This function defines the SQLite statement used to select all entries of this type.
    fn sql_select_all() -> &'static str;

    /// This function defines the SQLite statement used to update an entry of this type.
    fn sql_update(field: Self::UpdateField) -> &'static str;
}

// Implementations
/// All the fields of [Account] entries that may be updated.
pub enum AccountUpdateField {
    PasswordSalt,
    DblHashedPasswordHash,
    DblHashedPasswordSalt,
    EncryptedKeyCipherbytes,
    EncryptedKeyNonce,
}
impl HasSqlStatements for Account {
    type UpdateField = AccountUpdateField;

    fn sql_insert() -> &'static str {
        INSERT_ACCOUNT
    }

    fn sql_delete() -> &'static str {
        DELETE_ACCOUNT
    }

    fn sql_select() -> &'static str {
        SELECT_ACCOUNT
    }

    fn sql_select_all() -> &'static str {
        SELECT_ALL_ACCOUNTS
    }

    fn sql_update(field: Self::UpdateField) -> &'static str {
        match field {
            AccountUpdateField::PasswordSalt => UPDATE_ACCOUNT_PASSWORD_SALT,
            AccountUpdateField::DblHashedPasswordHash => UPDATE_ACCOUNT_DBL_HASHED_PASSWORD_HASH,
            AccountUpdateField::DblHashedPasswordSalt => UPDATE_ACCOUNT_DBL_HASHED_PASSWORD_SALT,
            AccountUpdateField::EncryptedKeyCipherbytes => UPDATE_ACCOUNT_ENCRYPTED_KEY_CIPHERBYTES,
            AccountUpdateField::EncryptedKeyNonce => UPDATE_ACCOUNT_ENCRYPTED_KEY_NONCE,
        }
    }
}

/// All the fields of [Credential] entries that may be updated.
#[allow(dead_code)]
pub enum CredentialUpdateField {
    UsernameCipherbytes,
    UsernameNonce,
    PasswordCipherbytes,
    PasswordNonce,
    NotesCipherbytes,
    NotesNonce,
}
impl HasSqlStatements for Credential {
    type UpdateField = CredentialUpdateField;

    fn sql_insert() -> &'static str {
        INSERT_CREDENTIAL
    }

    fn sql_delete() -> &'static str {
        DELETE_CREDENTIAL
    }

    fn sql_select() -> &'static str {
        SELECT_CREDENTIAL
    }

    fn sql_select_all() -> &'static str {
        SELECT_ALL_CREDENTIALS
    }

    fn sql_update(field: Self::UpdateField) -> &'static str {
        match field {
            CredentialUpdateField::UsernameCipherbytes => {
                UPDATE_CREDENTIAL_ENCRYPTED_USERNAME_CIPHERBYTES
            }
            CredentialUpdateField::UsernameNonce => UPDATE_CREDENTIAL_ENCRYPTED_USERNAME_NONCE,
            CredentialUpdateField::PasswordCipherbytes => {
                UPDATE_CREDENTIAL_ENCRYPTED_PASSWORD_CIPHERBYTES
            }
            CredentialUpdateField::PasswordNonce => UPDATE_CREDENTIAL_ENCRYPTED_PASSWORD_NONCE,
            CredentialUpdateField::NotesCipherbytes => {
                UPDATE_CREDENTIAL_ENCRYPTED_NOTES_CIPHERBYTES
            }
            CredentialUpdateField::NotesNonce => UPDATE_CREDENTIAL_ENCRYPTED_NOTES_NONCE,
        }
    }
}

/// All the fields of [FileData] entries that may be updated.
pub enum FileDataUpdateField {
    ContentsNonce,
}
impl HasSqlStatements for FileData {
    type UpdateField = FileDataUpdateField;

    fn sql_insert() -> &'static str {
        INSERT_FILE_DATA
    }

    fn sql_delete() -> &'static str {
        DELETE_FILE_DATA
    }

    fn sql_select() -> &'static str {
        SELECT_FILE_DATA
    }

    fn sql_select_all() -> &'static str {
        SELECT_ALL_FILES_DATA
    }

    fn sql_update(field: Self::UpdateField) -> &'static str {
        match field {
            FileDataUpdateField::ContentsNonce => UPDATE_FILE_DATA_CONTENTS_NONCE,
        }
    }
}

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
            self.username().into_b64(),
            self.password_salt().into_b64(),
            self.dbl_hashed_password().hash().into_b64(),
            self.dbl_hashed_password().salt().into_b64(),
            self.encrypted_key().cipherbytes().into_b64(),
            self.encrypted_key().nonce().into_b64(),
        ]
    }
}
impl IntoDatabase for Credential {
    type FixedSizeStringArray = [String; 9];
    fn into_database(self) -> Self::FixedSizeStringArray {
        [
            self.owner_username().into_b64(),
            self.encrypted_name().cipherbytes().into_b64(),
            self.encrypted_name().nonce().into_b64(),
            self.encrypted_username().cipherbytes().into_b64(),
            self.encrypted_username().nonce().into_b64(),
            self.encrypted_password().cipherbytes().into_b64(),
            self.encrypted_password().nonce().into_b64(),
            self.encrypted_notes().cipherbytes().into_b64(),
            self.encrypted_notes().nonce().into_b64(),
        ]
    }
}
impl IntoDatabase for FileData {
    type FixedSizeStringArray = [String; 4];
    fn into_database(self) -> Self::FixedSizeStringArray {
        [
            self.path().into_b64(),
            self.filename().into_b64(),
            self.owner_username().into_b64(),
            self.contents_nonce().into_b64(),
        ]
    }
}

/// This trait defines how the given struct gets converted from a vector of base-64-encoded strings
/// for retrieval from the database.
pub trait TryFromDatabase {
    /// This function determines how the struct gets converted into the database format.
    fn try_from_database(row: &rusqlite::Row) -> eyre::Result<Self>
    where
        Self: Sized;
}

// Implementations
impl TryFromDatabase for Account {
    fn try_from_database(row: &rusqlite::Row) -> eyre::Result<Self> {
        let username = b64_to_utf8(&row.get::<usize, String>(0)?)?;
        let password_salt = b64_to_fixed(&row.get::<usize, String>(1)?)?;
        let dbl_hashed_password =
            hashed_from_db(&row.get::<usize, String>(2)?, &row.get::<usize, String>(3)?)?;
        let encrypted_key =
            encrypted_from_db(&row.get::<usize, String>(4)?, &row.get::<usize, String>(5)?)?;

        Ok(Self::from_fields(
            username,
            password_salt,
            dbl_hashed_password,
            encrypted_key,
        ))
    }
}
impl TryFromDatabase for Credential {
    fn try_from_database(row: &rusqlite::Row) -> eyre::Result<Self> {
        let owner_username = b64_to_utf8(&row.get::<usize, String>(0)?)?;
        let encrypted_name =
            encrypted_from_db(&row.get::<usize, String>(1)?, &row.get::<usize, String>(2)?)?;
        let encrypted_username =
            encrypted_from_db(&row.get::<usize, String>(3)?, &row.get::<usize, String>(4)?)?;
        let encrypted_password =
            encrypted_from_db(&row.get::<usize, String>(5)?, &row.get::<usize, String>(6)?)?;
        let encrypted_notes =
            encrypted_from_db(&row.get::<usize, String>(7)?, &row.get::<usize, String>(8)?)?;

        Ok(Self::from_fields(
            owner_username,
            encrypted_name,
            encrypted_username,
            encrypted_password,
            encrypted_notes,
        ))
    }
}
impl TryFromDatabase for FileData {
    fn try_from_database(row: &rusqlite::Row) -> eyre::Result<Self> {
        let path = b64_to_utf8_path(&row.get::<usize, String>(0)?)?;
        let filename = b64_to_utf8(&row.get::<usize, String>(1)?)?;
        let owner_username = b64_to_utf8(&row.get::<usize, String>(2)?)?;
        let contents_nonce = b64_to_fixed(&row.get::<usize, String>(3)?)?;

        Ok(Self::from_fields(
            path,
            filename,
            owner_username,
            contents_nonce,
        ))
    }
}

// Helper function to get an [Encrypted] from database entries.
fn encrypted_from_db(b64_cipherbytes: &str, b64_nonce: &str) -> eyre::Result<Encrypted> {
    let cipherbytes: Vec<u8> = b64_to_bytes(b64_cipherbytes)?;
    let nonce: Aes256Nonce = b64_to_fixed(b64_nonce)?;
    Ok(Encrypted::from_fields(cipherbytes, nonce))
}

// Helper function to get a [Hashed] from database entries.
fn hashed_from_db<const H: usize, const S: usize>(
    b64_hash: &str,
    b64_salt: &str,
) -> eyre::Result<Hashed<H, S>> {
    let hash: Hash<H> = b64_to_fixed(b64_hash)?;
    let salt: Salt<S> = b64_to_fixed(b64_salt)?;
    Ok(Hashed::from_fields(hash, salt))
}

/// Implementors of this trait have entries that can be sorted and selected by an owning [Account]
/// username.
pub trait OwnedByAccount {
    // Denotes the SQLite statement for selecting all entries owned by the given account username.
    fn sql_select_owned() -> &'static str;
}

// Implementations
impl OwnedByAccount for Credential {
    fn sql_select_owned() -> &'static str {
        SELECT_ACCOUNT_CREDENTIALS
    }
}
impl OwnedByAccount for FileData {
    fn sql_select_owned() -> &'static str {
        SELECT_ACCOUNT_FILES_DATA
    }
}

/// Implementors of this trait can be converted to a base-64-encoded String.
pub trait IntoB64 {
    fn into_b64(self) -> String;
}

// Implementations
macro_rules! impl_into_b64_byte_vec {
    ($($t:ty),+) => {
        $(impl IntoB64 for $t {
            fn into_b64(self) -> String {
                let bytes_vec: Vec<u8> = self.into();
                Base64::encode_string(&bytes_vec)
            }
        })*
    }
}
impl_into_b64_byte_vec!(
    Vec<u8>,
    &[u8],
    String,
    &str,
    [u8; 64],
    Aes256Key,
    Aes256Nonce
);
macro_rules! impl_into_b64_camino {
    ($($t:ty),+) => {
        $(impl IntoB64 for $t {
            fn into_b64(self) -> String {
                let path: &Utf8Path = self.as_ref();
                Base64::encode_string(path.as_str().as_bytes())
            }
        })*
    }
}
impl_into_b64_camino!(Utf8PathBuf, &Utf8PathBuf, &Utf8Path);

// Helper function to convert b64 strings to UTF-8 path buffers.
fn b64_to_utf8_path(input: &str) -> eyre::Result<Utf8PathBuf> {
    Ok(Utf8PathBuf::from(b64_to_utf8(input)?))
}

// Helper function to convert b64 strings to UTF-8 strings.
fn b64_to_utf8(input: &str) -> eyre::Result<String> {
    Ok(String::from_utf8(b64_to_bytes(input)?)?)
}

// Helper function to convert b64 strings to fixed-length byte slices.
fn b64_to_fixed<const N: usize>(input: &str) -> eyre::Result<[u8; N]> {
    let bytes_vec: Vec<u8> = Base64::decode_vec(input)?;
    let len = bytes_vec.len();

    match bytes_vec.try_into() {
        Ok(slice) => Ok(slice),
        Err(_) => Err(eyre!("b64_to_fixed: Expected length {}, got {}.", N, len)),
    }
}

// Helper function to convert b64 strings to vectors of bytes.
fn b64_to_bytes(input: &str) -> eyre::Result<Vec<u8>> {
    Ok(Base64::decode_vec(input)?)
}
