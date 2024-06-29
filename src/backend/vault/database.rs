use std::{array::IntoIter, iter::Map};

use camino::Utf8Path;
use color_eyre::eyre::{self, eyre};
use rusqlite::{
    config::DbConfig, params_from_iter, Connection, OpenFlags, ParamsFromIter, Transaction,
};

use super::{database_traits::*, sql_schemas::*};

#[derive(Debug)]
pub struct Database {
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

        Ok(Self { connection })
    }

    /// Open a new database [Transaction].
    pub fn open_transaction(&mut self) -> eyre::Result<Transaction> {
        Ok(self.connection.transaction()?)
    }

    /// Retreive a specific entry based on the given primary key.
    ///
    /// Return [Ok<None>] if no entry with that primary key exists in the database.
    pub fn select_entry<T, U, const N: usize>(
        &self,
        primary_key_arr: [U; N],
    ) -> eyre::Result<Option<T>>
    where
        T: TryFromDatabase + HasSqlStatements,
        U: IntoB64,
    {
        let mut statement = self.connection.prepare(T::sql_select())?;
        let params = Self::get_params_iter(primary_key_arr);

        let query_result = statement.query_row(params_from_iter(params), |row| {
            Ok(T::try_from_database(row))
        });
        match query_result {
            Ok(entry) => Ok(Some(entry?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(eyre!("{err:?}")),
        }
    }

    /// Like [Database::select_entry], but return [Err] if no entries were found.
    pub fn select_entry_err_none<T, U, const N: usize>(
        &self,
        primary_key_arr: [U; N],
    ) -> eyre::Result<T>
    where
        T: TryFromDatabase + HasSqlStatements,
        U: IntoB64,
    {
        match self.select_entry(primary_key_arr) {
            Ok(Some(entry)) => Ok(entry),
            Ok(None) => Err(eyre!(
                "No entries in database found matching the given primary key."
            )),
            Err(err) => Err(err),
        }
    }

    /// Select all entries with a given foreign key.
    pub fn select_owned_entries<T, U, const N: usize>(
        &self,
        foreign_key_arr: [U; N],
    ) -> eyre::Result<Vec<T>>
    where
        T: TryFromDatabase + OwnedByAccount,
        U: IntoB64,
    {
        let mut statement = self.connection.prepare(T::sql_select_owned())?;
        let params = Self::get_params_iter(foreign_key_arr);
        let rows = statement.query_map(params_from_iter(params), |row| {
            Ok(T::try_from_database(row))
        })?;
        let mut results = Vec::new();
        for query_result in rows {
            results.push(query_result??);
        }
        Ok(results)
    }

    /// Delete a specific entry based on the given primary key.
    pub fn delete_entry<T, U, const N: usize>(&self, primary_key_arr: [U; N]) -> eyre::Result<()>
    where
        T: HasSqlStatements,
        U: IntoB64,
    {
        Self::connection_delete::<T, U, N>(primary_key_arr, &self.connection)
    }

    /// Delete a specific entry using the current [Transaction].
    pub fn transaction_delete<T, U, const N: usize>(
        primary_key_arr: [U; N],
        tx: &Transaction,
    ) -> eyre::Result<()>
    where
        T: HasSqlStatements,
        U: IntoB64,
    {
        Self::connection_delete::<T, U, N>(primary_key_arr, tx)
    }

    // Helper function— connection-agnostic delete.
    fn connection_delete<T, U, const N: usize>(
        primary_key_arr: [U; N],
        conn: &Connection,
    ) -> eyre::Result<()>
    where
        T: HasSqlStatements,
        U: IntoB64,
    {
        let mut statement = conn.prepare(T::sql_delete())?;
        let params = Self::get_params_iter(primary_key_arr);

        let num_rows = statement.execute(params_from_iter(params))?;

        if num_rows == 0 {
            Err(eyre!("The given params returned no rows to delete.",))
        } else {
            Ok(())
        }
    }

    /// Insert a specific entry into the matching table.
    pub fn insert_entry<T>(&self, entry: T) -> eyre::Result<()>
    where
        T: IntoDatabase + HasSqlStatements,
        T::FixedSizeStringArray: rusqlite::Params,
    {
        Self::connection_insert::<T>(entry, &self.connection)
    }

    /// Insert a specific entry using the current [Transaction].
    pub fn transaction_insert<T>(entry: T, tx: &Transaction) -> eyre::Result<()>
    where
        T: IntoDatabase + HasSqlStatements,
        T::FixedSizeStringArray: rusqlite::Params,
    {
        Self::connection_insert::<T>(entry, tx)
    }

    // Helper function— connection-agnostic delete.
    fn connection_insert<T>(entry: T, conn: &Connection) -> eyre::Result<()>
    where
        T: IntoDatabase + HasSqlStatements,
        T::FixedSizeStringArray: rusqlite::Params,
    {
        let num_rows = conn.execute(T::sql_insert(), entry.into_database())?;
        if num_rows == 0 {
            Err(eyre!("Failed to insert row."))
        } else if num_rows == 1 {
            Ok(())
        } else {
            Err(eyre!("Somehow, more than one element was inserted..."))
        }
    }

    // Helper function to get SQLite params from an array.
    fn get_params_iter<U, const N: usize>(
        params_arr: [U; N],
    ) -> Map<IntoIter<U, N>, impl FnMut(U) -> String>
    where
        U: IntoB64,
    {
        params_arr.into_iter().map(|e| e.into_b64())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, remove_file, File},
        io::Write,
    };

    use camino::{Utf8Path, Utf8PathBuf};
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

    fn test_db_path(path_str: &str) -> Utf8PathBuf {
        Utf8PathBuf::from(path_str)
    }

    fn refresh_test_db(path_str: &str) -> Database {
        let _ = fs::remove_file(test_db_path(path_str));
        fs::File::create_new(test_db_path(path_str)).unwrap();
        Database::connect(test_db_path(path_str)).unwrap()
    }

    fn make_a_file(path: &Utf8Path, bytes: &[u8]) -> eyre::Result<()> {
        let mut f = File::create_new(path)?;
        f.write_all(bytes)?;
        Ok(())
    }

    fn delete_a_file(path: &Utf8Path) -> eyre::Result<()> {
        remove_file(path)?;
        Ok(())
    }

    #[test]
    fn account_to_from() {
        let db_path = "tests/account_to_from.db";
        let db = refresh_test_db(db_path);

        let username = "Mister Test";
        let password = "I'm the great Mister Test, I don't need a password!";
        let account = Account::new(username, password).unwrap();

        db.insert_entry(account.clone()).unwrap();
        let loaded_account: Account = db.select_entry([username]).unwrap().unwrap();

        assert_eq!(account, loaded_account);

        assert_eq!(loaded_account.username(), username);
    }

    #[test]
    fn credential_to_from() {
        let db_path = "tests/credential_to_from.db";
        let db = refresh_test_db(db_path);

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
        let _ = db.insert_entry(cred.clone()).unwrap_err();

        let account = Account::new(owner_username, owner_password).unwrap();
        let other_account = Account::new(different_owner_username, owner_password).unwrap();

        db.insert_entry(other_account.clone()).unwrap();

        // There is still no account that matches. Should still fail.
        let _ = db.insert_entry(cred.clone()).unwrap_err();

        db.insert_entry(account.clone()).unwrap();

        db.insert_entry(cred.clone()).unwrap();
        let loaded_cred: Credential = db
            .select_entry([
                cred.owner_username().as_bytes(),
                cred.encrypted_name().cipherbytes(),
            ])
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
        let db_path = "tests/file_data_to_from.db";
        let db = refresh_test_db(db_path);

        let path = Utf8PathBuf::from("src/backend/vault/database_traits.rs");
        let filename = String::from("database_traits.rs");
        let owner_username = String::from("i'm da owner");
        let owner_password = "open sesame!";
        let (encrypted_contents, key) = "test".try_encrypt_new_key().unwrap();
        let contents_nonce = encrypted_contents.nonce();

        let account = Account::new(&owner_username, owner_password).unwrap();
        db.insert_entry(account).unwrap();

        let file_data = FileData::new(
            path.clone(),
            filename.clone(),
            owner_username.clone(),
            contents_nonce,
        );

        db.insert_entry(file_data.clone()).unwrap();
        let loaded_file_data = db.select_entry([&path]).unwrap().unwrap();

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

    #[test]
    fn delete() {
        let db_path = "tests/delete.db";
        let db = refresh_test_db(db_path);

        let dir = Utf8PathBuf::from("tests/");

        let uname_1 = "mr_test";
        let pwd_1 = "i_love_testing_123";
        let acc_1 = Account::new(uname_1, pwd_1).unwrap();
        db.insert_entry(acc_1.clone()).unwrap();

        let uname_2 = "mr_awesome";
        let pwd_2 = "i am so so awesome!";
        let acc_2 = Account::new(uname_2, pwd_2).unwrap();
        db.insert_entry(acc_2.clone()).unwrap();

        let filename_1_1 = "f_1_1";
        let mut path_1_1 = dir.clone();
        path_1_1.push(filename_1_1);
        let (contents_1_1, key_1_1) = "test".try_encrypt_new_key().unwrap();
        let f_1_1 = FileData::new(
            &path_1_1,
            "f_1_1".to_string(),
            uname_1.to_string(),
            contents_1_1.nonce(),
        );
        db.insert_entry(f_1_1.clone()).unwrap();

        let filename_1_2 = "f_1_2";
        let mut path_1_2 = dir.clone();
        path_1_2.push(filename_1_2);
        let contents_1_2 = "test".try_encrypt_with_key(key_1_1).unwrap();
        let f_1_2 = FileData::new(
            &path_1_2,
            "f_1_2".to_string(),
            uname_1.to_string(),
            contents_1_2.nonce(),
        );
        db.insert_entry(f_1_2.clone()).unwrap();

        let filename_2_1 = "f_2_1";
        let mut path_2_1 = dir.clone();
        path_2_1.push(filename_2_1);
        let (contents_2_1, key_2_1) = "test".try_encrypt_new_key().unwrap();
        let f_2_1 = FileData::new(
            &path_2_1,
            "f_2_1".to_string(),
            uname_2.to_string(),
            contents_2_1.nonce(),
        );
        db.insert_entry(f_2_1.clone()).unwrap();

        let cred_1 = Credential::try_new(uname_1, key_1_1, "cred_1", "u1", "p1", "").unwrap();
        db.insert_entry(cred_1.clone()).unwrap();
        let cred_2 = Credential::try_new(uname_2, key_2_1, "cred_2", "u2", "p2", "").unwrap();
        db.insert_entry(cred_2.clone()).unwrap();

        assert!(db
            .select_entry::<Account, &str, 1>([uname_1])
            .unwrap()
            .is_some());
        assert!(db
            .select_entry::<FileData, &Utf8Path, 1>([&path_1_1])
            .unwrap()
            .is_some());
        assert!(db
            .select_entry::<Credential, &[u8], 2>([
                cred_1.owner_username().as_bytes(),
                cred_1.encrypted_name().cipherbytes()
            ])
            .unwrap()
            .is_some());

        db.delete_entry::<Account, &str, 1>([uname_1]).unwrap();
        db.select_entry_err_none::<Account, &str, 1>([uname_1])
            .unwrap_err();
        assert!(db
            .select_entry::<Account, &str, 1>([uname_1])
            .unwrap()
            .is_none());
        assert!(db
            .select_entry::<Credential, &[u8], 2>([
                cred_1.owner_username().as_bytes(),
                cred_1.encrypted_name().cipherbytes()
            ])
            .unwrap()
            .is_none());
        assert!(db
            .select_entry::<FileData, &Utf8Path, 1>([&path_1_1])
            .unwrap()
            .is_none());
        assert!(db
            .select_entry::<FileData, &Utf8Path, 1>([&path_1_2])
            .unwrap()
            .is_none());
        assert!(db
            .select_entry::<Account, &str, 1>([uname_2])
            .unwrap()
            .is_some());
        assert!(db
            .select_entry::<FileData, &Utf8Path, 1>([&path_2_1])
            .unwrap()
            .is_some());
        assert!(db
            .select_entry::<Credential, &[u8], 2>([
                cred_2.owner_username().as_bytes(),
                cred_2.encrypted_name().cipherbytes()
            ])
            .unwrap()
            .is_some());

        db.delete_entry::<Credential, &[u8], 2>([
            cred_2.owner_username().as_bytes(),
            cred_2.encrypted_name().cipherbytes(),
        ])
        .unwrap();
        assert!(db
            .select_entry::<Account, &str, 1>([uname_2])
            .unwrap()
            .is_some());
        assert!(db
            .select_entry::<FileData, &Utf8Path, 1>([&path_2_1])
            .unwrap()
            .is_some());
        assert!(db
            .select_entry::<Credential, &[u8], 2>([
                cred_2.owner_username().as_bytes(),
                cred_2.encrypted_name().cipherbytes()
            ])
            .unwrap()
            .is_none());

        db.delete_entry::<FileData, &Utf8Path, 1>([&path_2_1])
            .unwrap();
        assert!(db
            .select_entry::<Account, &str, 1>([uname_2])
            .unwrap()
            .is_some());
        assert!(db
            .select_entry::<FileData, &Utf8Path, 1>([&path_2_1])
            .unwrap()
            .is_none());
        assert!(db
            .select_entry::<Credential, &[u8], 2>([
                cred_2.owner_username().as_bytes(),
                cred_2.encrypted_name().cipherbytes()
            ])
            .unwrap()
            .is_none());
    }

    #[test]
    fn rollback_delete_fail() {
        let file_path = Utf8PathBuf::from("tests/delete-rollback-test.txt");
        let _ = delete_a_file(&file_path);

        let db_path = "tests/rollback_delete_fail.db";
        let mut db = refresh_test_db(db_path);

        let username = "abc";
        let password = "123";
        let account = Account::new(username, password).unwrap();

        db.insert_entry(account).unwrap();
        make_a_file(&file_path, b"blah blah blah").unwrap();
        fs::metadata(&file_path).unwrap();

        let tx = db.open_transaction().unwrap();
        match Database::transaction_delete::<Credential, &str, 1>(
            ["wrong primary key field count! please preserve my file!"],
            &tx,
        ) {
            Ok(_) => match delete_a_file(&file_path) {
                Ok(_) => tx.commit().unwrap(),
                Err(_) => panic!("Should not have succeeded."),
            },
            Err(_) => tx.rollback().unwrap(),
        };
        fs::metadata(&file_path).unwrap();

        let tx = db.open_transaction().unwrap();
        match Database::transaction_delete::<Account, &str, 1>(
            ["misspelled username! i hope my file doesn't actually get deleted!"],
            &tx,
        ) {
            Ok(_) => match delete_a_file(&file_path) {
                Ok(_) => tx.commit().unwrap(),
                Err(_) => panic!("Should not have succeeded."),
            },

            Err(_) => tx.rollback().unwrap(),
        };
        fs::metadata(&file_path).unwrap();

        let tx = db.open_transaction().unwrap();
        match Database::transaction_delete::<Account, &str, 1>(["abc"], &tx) {
            Ok(_) => match delete_a_file(&Utf8PathBuf::from("examples")) {
                Ok(_) => tx.commit().unwrap(),
                Err(_) => tx.rollback().unwrap(),
            },
            Err(_) => panic!("Should not have failed."),
        }

        let tx = db.open_transaction().unwrap();
        match Database::transaction_delete::<Account, &str, 1>(["abc"], &tx) {
            Ok(_) => match delete_a_file(&Utf8PathBuf::from(&file_path)) {
                Ok(_) => tx.commit().unwrap(),
                Err(_) => tx.rollback().unwrap(),
            },
            Err(_) => panic!("Should not have failed."),
        }

        fs::metadata(&file_path).unwrap_err();
    }

    #[test]
    fn rollback_insert_fail() {
        let file_path = Utf8PathBuf::from("tests/insert-rollback-test.txt");
        let _ = delete_a_file(&file_path);

        let db_path = "tests/rollback_insert_fail.db";
        let mut db = refresh_test_db(db_path);

        let username = "abc";
        let password = "123";
        let account = Account::new(username, password).unwrap();

        let tx = db.open_transaction().unwrap();
        Database::transaction_insert(account, &tx).unwrap();
        make_a_file(&file_path, b"blah blah blah").unwrap();
        tx.commit().unwrap();

        db.select_entry::<Account, &str, 1>([username]).unwrap();
        fs::metadata(&file_path).unwrap();

        let username2 = "def";
        let password2 = "456";
        let account2 = Account::new(username2, password2).unwrap();

        assert!(db
            .select_entry::<Account, &str, 1>([username2])
            .unwrap()
            .is_none());

        let tx = db.open_transaction().unwrap();
        Database::transaction_insert(account2, &tx).unwrap();
        match make_a_file(&file_path, b"should fail!") {
            Ok(_) => tx.commit().unwrap(),
            Err(_) => tx.rollback().unwrap(),
        };

        db.select_entry::<Account, &str, 1>([username]).unwrap();
        assert!(db
            .select_entry::<Account, &str, 1>([username2])
            .unwrap()
            .is_none());
    }
}
