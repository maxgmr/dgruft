//! These traits determine how different types can be converted into types accepted by the `dgruft`
//! database.

use base64ct::{Base64, Encoding};
use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{self, eyre};

use super::super::{
    account::Account,
    credential::Credential,
    encryption::encrypted::{Aes256Key, Aes256Nonce, Encrypted},
    file_data::FileData,
    hashing::hashed::{Hash, Hashed, Salt},
};

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
    type FixedSizeStringArray;

    /// This function determines how the struct gets converted into the database format.
    fn try_from_database(db_arr: Self::FixedSizeStringArray) -> eyre::Result<Self>
    where
        Self: Sized;
}

// Implementations
impl TryFromDatabase for Account {
    type FixedSizeStringArray = [String; 6];

    fn try_from_database(db_arr: Self::FixedSizeStringArray) -> eyre::Result<Self> {
        let username = b64_to_utf8(&db_arr[0])?;
        let password_salt = b64_to_fixed(&db_arr[1])?;
        let dbl_hashed_password = hashed_from_db(&db_arr[2], &db_arr[3])?;
        let encrypted_key = encrypted_from_db(&db_arr[4], &db_arr[5])?;

        Ok(Self::from_fields(
            username,
            password_salt,
            dbl_hashed_password,
            encrypted_key,
        ))
    }
}
impl TryFromDatabase for Credential {
    type FixedSizeStringArray = [String; 9];

    fn try_from_database(db_arr: Self::FixedSizeStringArray) -> eyre::Result<Self> {
        let owner_username = b64_to_utf8(&db_arr[0])?;
        let encrypted_name = encrypted_from_db(&db_arr[1], &db_arr[2])?;
        let encrypted_username = encrypted_from_db(&db_arr[3], &db_arr[4])?;
        let encrypted_password = encrypted_from_db(&db_arr[5], &db_arr[6])?;
        let encrypted_notes = encrypted_from_db(&db_arr[7], &db_arr[8])?;

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
    type FixedSizeStringArray = [String; 4];

    fn try_from_database(db_arr: Self::FixedSizeStringArray) -> eyre::Result<Self> {
        let path = b64_to_utf8_path(&db_arr[0])?;
        let filename = b64_to_utf8(&db_arr[1])?;
        let owner_username = b64_to_utf8(&db_arr[2])?;
        let contents_nonce = b64_to_fixed(&db_arr[3])?;

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

/// Implementors of this trait can be converted to a base-64-encoded String.
pub trait IntoB64 {
    fn into_b64(self) -> String;
}

// Implementations.
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
impl_into_b64_byte_vec!(Vec<u8>, &[u8], String, &str, Aes256Key, Aes256Nonce);
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
impl_into_b64_camino!(Utf8PathBuf, &Utf8Path);

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

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::backend::encryption::encrypted::TryFromEncrypted;

    use super::{
        super::super::encryption::encrypted::{new_rand_key, TryIntoEncrypted},
        *,
    };

    #[test]
    fn account_to_from() {
        let username = "Mister Test";
        let password = "I'm the great Mister Test, I don't need a password!";
        let account = Account::new(username, password).unwrap();

        let db_account = account.clone().into_database();
        let loaded_account = Account::try_from_database(db_account).unwrap();

        assert_eq!(account, loaded_account);
        assert_eq!(loaded_account.username(), username);
    }

    #[test]
    fn credential_to_from() {
        let owner_username = "mister_owner_123";
        let key = new_rand_key();
        let name = "maxgmr.ca login info";
        let username = "im_da_admin";
        let password = "blahblahblah";
        let notes = "dgruft很酷。";

        let cred =
            Credential::try_new(owner_username, key, name, username, password, notes).unwrap();

        let db_cred = cred.clone().into_database();
        let loaded_cred = Credential::try_from_database(db_cred).unwrap();

        assert_eq!(cred, loaded_cred);

        assert_eq!(loaded_cred.name::<String>(key).unwrap(), name);
        assert_eq!(loaded_cred.username::<String>(key).unwrap(), username);
        assert_eq!(loaded_cred.password::<String>(key).unwrap(), password);
        assert_eq!(loaded_cred.notes::<String>(key).unwrap(), notes);
    }

    #[test]
    fn file_data_to_from() {
        let path = Utf8PathBuf::from("src/backend/vault/database_traits.rs");
        let filename = String::from("database_traits.rs");
        let owner_username = String::from("i'm da owner");
        let (encrypted_contents, key) = "test".try_encrypt_new_key().unwrap();
        let contents_nonce = encrypted_contents.nonce();

        let file_data = FileData::new(
            path.clone(),
            filename.clone(),
            owner_username.clone(),
            contents_nonce,
        );

        let db_file_data = file_data.clone().into_database();
        let loaded_file_data = FileData::try_from_database(db_file_data).unwrap();

        assert_eq!(file_data, loaded_file_data);

        assert_eq!(path, loaded_file_data.path());
        assert_eq!(filename, loaded_file_data.filename());
        assert_eq!(owner_username, loaded_file_data.owner_username());
        assert_eq!(contents_nonce, loaded_file_data.contents_nonce());

        let decrypted_contents = String::try_decrypt(
            &Encrypted::from_fields(
                encrypted_contents.cipherbytes().to_vec(),
                loaded_file_data.contents_nonce(),
            ),
            key,
        )
        .unwrap();
        assert_eq!(decrypted_contents, "test");
    }
}
