use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{self, eyre};
use rusqlite::{config::DbConfig, Connection, OpenFlags};

use super::{database_traits::*, sql_schemas::*, sql_statements::*};

/// All the tables stored in the [Database]. Used to determine [Database] function behaviour.
pub enum Table {
    Accounts,
    Credentials,
    FilesData,
}

#[derive(Debug)]
pub struct Database {
    /// Path to .db file.
    path: Utf8PathBuf,
    /// SQLite database connection.
    connection: Connection,
}
impl Database {
    /// Open a new connection to the database at the given path.
    pub fn connect<P>(path: P) -> eyre::Result<Self>
    where
        P: AsRef<Utf8Path>,
    {
        let connection = Connection::open_with_flags(
            path.as_ref(),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, true)?;

        // Create tables iff they don't exist
        connection.execute(CREATE_ACCOUNTS, ())?;
        connection.execute(CREATE_CREDENTIALS, ())?;
        connection.execute(CREATE_FILES_DATA, ())?;

        Ok(Self {
            path: path.as_ref().to_path_buf(),
            connection,
        })
    }

    /// Retreive a specific entry based on the given primary key.
    ///
    /// Return [Ok<None>] if no entry with that primary key exists in the database.
    pub fn select_entry<T, U, const N: usize>(
        &self,
        table: Table,
        primary_key_arr: [U; N],
    ) -> eyre::Result<Option<T>>
    where
        T: TryFromDatabase,
        U: IntoB64,
    {
        let sql_statement = match table {
            Table::Accounts => GET_ACCOUNT,
            Table::Credentials => GET_CREDENTIAL,
            Table::FilesData => GET_FILE_DATA,
        };
        let mut statement = self.connection.prepare(sql_statement)?;

        let b64_key_iter = primary_key_arr.into_iter().map(|e| e.into_b64());

        let query_result = statement.query_row(rusqlite::params_from_iter(b64_key_iter), |row| {
            Ok(T::try_from_database(row))
        });
        match query_result {
            Ok(entry) => Ok(Some(entry?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(eyre!("{err:?}")),
        }
    }

    /// Insert a specific entry into the matching table.
    ///
    /// Return [Err] if there is a conflict.
    pub fn insert_entry<T>(&self, table: Table, entry: T) -> eyre::Result<()>
    where
        T: IntoDatabase,
        T::FixedSizeStringArray: rusqlite::Params,
    {
        let sql_statement = match table {
            Table::Accounts => INSERT_ACCOUNT,
            Table::Credentials => INSERT_CREDENTIAL,
            Table::FilesData => INSERT_FILE_DATA,
        };
        self.connection
            .execute(sql_statement, entry.into_database())?;
        Ok(())
    }
}

// Run with `cargo t -- --test-threads=1`
#[cfg(test)]
mod tests {
    use std::fs;

    use pretty_assertions::assert_eq;

    use super::{
        super::super::{
            account::Account,
            credential::Credential,
            encryption::encrypted::{new_rand_key, Encrypted, TryFromEncrypted, TryIntoEncrypted},
            file_data::FileData,
        },
        *,
    };

    const TEST_DB_PATH_STR: &str = "tests/unit-test-db.db";

    fn test_db_path() -> Utf8PathBuf {
        Utf8PathBuf::from(TEST_DB_PATH_STR)
    }

    fn refresh_test_db() -> Database {
        let _ = fs::remove_file(test_db_path());
        fs::File::create_new(test_db_path()).unwrap();
        Database::connect(test_db_path()).unwrap()
    }

    #[test]
    fn test_db_connect() {
        let db = refresh_test_db();
        assert_eq!(db.path, test_db_path());
    }

    #[test]
    fn account_to_from() {
        let db = refresh_test_db();

        let username = "Mister Test";
        let password = "I'm the great Mister Test, I don't need a password!";
        let account = Account::new(username, password).unwrap();

        db.insert_entry(Table::Accounts, account.clone()).unwrap();
        let loaded_account: Account = db
            .select_entry(Table::Accounts, [username])
            .unwrap()
            .unwrap();

        assert_eq!(account, loaded_account);

        assert_eq!(loaded_account.username(), username);
    }

    #[test]
    fn credential_to_from() {
        let db = refresh_test_db();

        let owner_username = "mister_owner_123";
        let owner_password = "123";
        let different_owner_username = "not_mister_owner";
        let key = new_rand_key();
        let name = "maxgmr.ca login info";
        let username = "im_da_admin";
        let password = "blahblahblah";
        let notes = "dgruft很酷。";

        let cred =
            Credential::try_new(owner_username, key, name, username, password, notes).unwrap();

        // Trying to insert a credential without an existing, matching account should fail.
        let _ = db
            .insert_entry(Table::Credentials, cred.clone())
            .unwrap_err();

        let account = Account::new(owner_username, owner_password).unwrap();
        let other_account = Account::new(different_owner_username, owner_password).unwrap();

        db.insert_entry(Table::Accounts, other_account.clone())
            .unwrap();

        // There is still no account that matches. Should still fail.
        let _ = db
            .insert_entry(Table::Credentials, cred.clone())
            .unwrap_err();

        db.insert_entry(Table::Accounts, account.clone()).unwrap();

        db.insert_entry(Table::Credentials, cred.clone()).unwrap();
        let loaded_cred: Credential = db
            .select_entry(
                Table::Credentials,
                [
                    cred.owner_username().as_bytes(),
                    cred.encrypted_name().cipherbytes(),
                ],
            )
            .unwrap()
            .unwrap();

        assert_eq!(cred, loaded_cred);

        assert_eq!(loaded_cred.name::<String>(key).unwrap(), name);
        assert_eq!(loaded_cred.username::<String>(key).unwrap(), username);
        assert_eq!(loaded_cred.password::<String>(key).unwrap(), password);
        assert_eq!(loaded_cred.notes::<String>(key).unwrap(), notes);
    }

    #[test]
    fn file_data_to_from() {
        let db = refresh_test_db();

        let path = Utf8PathBuf::from("src/backend/vault/database_traits.rs");
        let filename = String::from("database_traits.rs");
        let owner_username = String::from("i'm da owner");
        let owner_password = "open sesame!";
        let (encrypted_contents, key) = "test".try_encrypt_new_key().unwrap();
        let contents_nonce = encrypted_contents.nonce();

        let account = Account::new(&owner_username, owner_password).unwrap();
        db.insert_entry(Table::Accounts, account).unwrap();

        let file_data = FileData::new(
            path.clone(),
            filename.clone(),
            owner_username.clone(),
            contents_nonce,
        );

        db.insert_entry(Table::FilesData, file_data.clone())
            .unwrap();
        let loaded_file_data = db.select_entry(Table::FilesData, [&path]).unwrap().unwrap();

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
