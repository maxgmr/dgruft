use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{self};
use rusqlite::{config::DbConfig, Connection, OpenFlags};

use super::{sql_schemas::*, sql_statements::*};

pub enum Table {
    Accounts,
    FilesData,
    Credentials,
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
        // connection.execute(CREATE_ACCOUNTS, ())?;
        // connection.execute(CREATE_FILES_DATA, ())?;
        // connection.execute(CREATE_CREDENTIALS, ())?;

        Ok(Self {
            path: path.as_ref().to_path_buf(),
            connection,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::fs;

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
}
