//! All functionality related to the [sqlite] database dgruft uses for persistence.
use rusqlite::{Connection, OpenFlags};
use std::ffi::OsStr;
use std::fmt::Display;
use std::path::{Path, PathBuf};

use crate::backend::sql_schemas::*;
use crate::backend::sql_statements::*;
use crate::backend::{account::Account, hashed, salt};

#[derive(Debug)]
/// Connection interface to the database.
pub struct Database {
    /// Path to .db file
    path: PathBuf,
    /// SQLite database connection
    connection: Connection,
}
impl Database {
    /// Open a new connection to the database at the given path.
    pub fn connect<P>(path: P) -> rusqlite::Result<Self>
    where
        P: AsRef<Path> + AsRef<OsStr> + Display,
    {
        // Don't create a new .db file if no db exists at the chosen path
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.execute(CREATE_USER_CREDENTIALS, ())?;
        Ok(Self {
            path: PathBuf::from(&path),
            connection,
        })
    }

    /// Retrieve account credentials from the database as [Account].
    pub fn get_account(&self, username: &str) -> rusqlite::Result<Option<Account>> {
        let mut statement = self.connection.prepare(GET_ACCOUNT)?;
        let account_result = statement.query_row([username], |row| {
            Ok(Account::load(
                &row.get::<usize, String>(0)?,
                hashed::Hashed::from_string(
                    &row.get::<usize, String>(1)?,
                    Some(salt::Salt::from_string(&row.get::<usize, String>(2)?).unwrap()),
                    hashed::hash_fn_from_string(&row.get::<usize, String>(3)?).unwrap(),
                )
                .unwrap(),
            ))
        });
        match account_result {
            Ok(account) => Ok(Some(account)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Add an [Account] to the `user_credentials` database table.
    /// Return [Err] if that account already exists.
    pub fn add_new_account(&mut self, account: Account) -> rusqlite::Result<()> {
        self.connection.execute(
            INSERT_NEW_ACCOUNT,
            (
                account.get_username(),
                account.get_password().get_str(),
                account.get_salt().as_ref().unwrap().get_str(),
                hashed::hash_fn_to_string(account.get_hash_fn()),
            ),
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    fn clear_all_tables(&mut self) -> usize {
        // Get list of all table names
        let mut statement = self.connection.prepare(SELECT_ALL_TABLES).unwrap();
        let table_names = statement
            .query_map([], |row| row.get::<usize, String>(0))
            .unwrap()
            .collect::<Vec<Result<String, rusqlite::Error>>>();
        statement.finalize().unwrap();
        // Drop each table
        let mut drop_count: usize = 0;
        for table in table_names {
            drop_count += 1;
            self.connection
                .execute(&format!("DROP TABLE IF EXISTS {}", &table.unwrap()), [])
                .unwrap();
        }
        drop_count
    }

    /// Get the path at which this [Database] is located.
    pub fn get_path(&self) -> &PathBuf {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rusqlite::ErrorCode;

    fn test_db() -> Database {
        Database::connect("./dbs/dgruft-test.db").unwrap()
    }

    fn clear_test_db() {
        let mut db = Database::connect("./dbs/dgruft-test.db").unwrap();
        db.clear_all_tables();
    }

    fn test_password() -> hashed::Hashed {
        hashed::Hashed::new(
            "my password",
            hashed::HashFn::Sha256,
            Some(&salt::Salt::new(16)),
        )
        .unwrap()
    }

    #[test]
    fn test_dne() {
        let err = Database::connect("./not/a/real/path/test.db").unwrap_err();

        if let Some(ErrorCode::CannotOpen) = err.sqlite_error_code() {
        } else {
            dbg!(&err);
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_clear() {
        clear_test_db();
        let mut test_db = test_db();
        assert_eq!(test_db.clear_all_tables(), 1);
        assert_eq!(test_db.clear_all_tables(), 0);
    }

    #[test]
    fn test_add_account() {
        clear_test_db();
        let mut test_db = test_db();
        test_db
            .add_new_account(Account::load("mister_awesome123", test_password()))
            .unwrap();
        let err = test_db
            .add_new_account(Account::load("mister_awesome123", test_password()))
            .unwrap_err();
        if let Some(ErrorCode::ConstraintViolation) = err.sqlite_error_code() {
        } else {
            dbg!(&err);
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_get_account() {
        clear_test_db();
        let mut test_db = test_db();
        test_db
            .add_new_account(Account::load("account1", test_password()))
            .unwrap();
        test_db
            .add_new_account(Account::load("account2", test_password()))
            .unwrap();

        let account1 = test_db.get_account("account1").unwrap().unwrap();
        let account2 = test_db.get_account("account2").unwrap().unwrap();

        assert_eq!(account1.get_username(), "account1");
        assert_eq!(account2.get_username(), "account2");

        assert_eq!(
            account1.get_password().get_str(),
            hashed::Hashed::from_string(
                account1.get_password().get_str(),
                account1.get_password().get_salt().clone(),
                *account1.get_password().get_hash_fn()
            )
            .unwrap()
            .get_str()
        );
        assert_eq!(
            account2.get_password().get_str(),
            hashed::Hashed::from_string(
                account2.get_password().get_str(),
                account2.get_password().get_salt().clone(),
                *account2.get_password().get_hash_fn()
            )
            .unwrap()
            .get_str()
        );
    }
}
