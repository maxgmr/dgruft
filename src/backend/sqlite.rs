//! All functionality related to the [sqlite] database dgruft uses for persistence.
use rusqlite::Connection;
use std::ffi::OsStr;
use std::fmt::Display;
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

use crate::backend::account::Account;
use crate::backend::sql_statements::*;

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
    pub fn connect<P>(path: P) -> std::io::Result<Self>
    where
        P: AsRef<Path> + AsRef<OsStr> + Display,
    {
        // Don't create a new .db file if no db exists at the chosen path
        if fs::metadata(&path).is_err() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("No SQLite database found at \"{}\".", path),
            ));
        }
        let database_result = match Connection::open(&path) {
            Ok(connection) => Ok(Self {
                path: PathBuf::from(&path),
                connection,
            }),
            Err(e) => Err(Error::new(ErrorKind::InvalidInput, e.to_string())),
        };
        if let Ok(database) = &database_result {
            // Create user credentials table if it doesn't already exist
            database
                .connection
                .execute(CREATE_USER_CREDENTIALS, ())
                .unwrap();
        }
        database_result
    }

    /// Add an [Account] to the `user_credentials` database table.
    /// Return [Err] if that account already exists.
    pub fn add_new_account(&mut self, account: Account) -> std::io::Result<()> {
        // TODO
        Ok(())
    }

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

    fn test_db() -> Database {
        Database::connect("./dbs/dgruft-test.db").unwrap()
    }

    #[test]
    fn test_dne() {
        let err = Database::connect("./not/a/real/path/test.db").unwrap_err();

        if let ErrorKind::NotFound = err.kind() {
        } else {
            dbg!(&err);
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_clear() {
        let mut test_db = test_db();
        assert_eq!(test_db.clear_all_tables(), 1);
        assert_eq!(test_db.clear_all_tables(), 0);
    }
}
