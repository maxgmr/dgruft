//! All functionality related to the [sqlite] database dgruft uses for persistence.
use sqlite::{Connection, State};
use std::ffi::OsStr;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

use crate::backend::account::Account;
use crate::backend::sql_statements::*;

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
        P: AsRef<Path> + AsRef<OsStr>,
    {
        let opened = sqlite::open(&path);
        let database_result = match opened {
            Ok(connection) => Ok(Self {
                path: PathBuf::from(&path),
                connection,
            }),
            Err(e) => Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "{} {}",
                    e.code.unwrap_or(0_isize),
                    e.message.unwrap_or("".to_owned())
                ),
            )),
        };
        if let Ok(database) = &database_result {
            database
                .connection
                .execute(CREATE_USER_CREDENTIALS)
                .unwrap();
        }
        database_result
    }

    /// Add an [Account] to the `user_credentials` database table.
    ///
    /// Returns [Err] if that account already exists.
    pub fn add_new_account(&mut self, account: Account) -> std::io::Result<()> {
        Ok(())
    }

    fn clear_all_tables(&mut self) -> usize {
        let mut statement = self.connection.prepare(SELECT_ALL_TABLES).unwrap();
        let mut table_commands: Vec<String> = Vec::new();
        while let Ok(State::Row) = statement.next() {
            table_commands.push(format!(
                "DROP TABLE IF EXISTS {}",
                statement.read::<String, _>("name").unwrap()
            ));
        }
        for command in &table_commands {
            self.connection.execute(command).unwrap();
        }
        table_commands.len()
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
    fn test_clear() {
        let mut test_db = test_db();
        assert_eq!(test_db.clear_all_tables(), 1);
        assert_eq!(test_db.clear_all_tables(), 0);
    }
}
