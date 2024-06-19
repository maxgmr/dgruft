//! All functionality related to the [SQLite](https://www.sqlite.org/about.html) database dgruft uses for persistence.
use std::ffi::OsStr;
use std::fmt::Display;
use std::path::{Path, PathBuf};

use rusqlite::{config::DbConfig, Connection, OpenFlags};

use crate::{
    backend::{
        account::Base64Account, password::Base64Password, sql_schemas::*, sql_statements::*,
    },
    helpers,
};

/// Connection interface to an SQLite database.
#[derive(Debug)]
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
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, true)?;

        // Create tables if they don't exist
        connection.execute(CREATE_USER_CREDENTIALS, ())?;
        connection.execute(CREATE_PASSWORDS, ())?;
        connection.execute(CREATE_FILES, ())?;
        Ok(Self {
            path: PathBuf::from(&path),
            connection,
        })
    }

    /// Retrieve a user's stored passwords from the database as a [Vec] of [Base64Password].
    /// Return [`Ok<None>`] if no account with that username exists.
    /// Return [Err] on a database error.
    pub fn get_b64_passwords(
        &self,
        username: &str,
    ) -> rusqlite::Result<Option<Vec<Base64Password>>> {
        // Ensure account exists
        if let Err(rusqlite::Error::QueryReturnedNoRows) = self.get_b64_account(username) {
            return Ok(None);
        };

        let mut statement = self.connection.prepare(GET_USER_PASSWORDS)?;
        let rows = statement.query_map([helpers::bytes_to_b64(username.as_bytes())], |row| {
            Ok(Base64Password {
                b64_owner_username: row.get::<usize, String>(0)?,
                b64_name_ciphertext: row.get::<usize, String>(0)?,
                b64_username_ciphertext: row.get::<usize, String>(0)?,
                b64_content_ciphertext: row.get::<usize, String>(0)?,
                b64_notes_ciphertext: row.get::<usize, String>(0)?,
                b64_name_nonce: row.get::<usize, String>(0)?,
                b64_username_nonce: row.get::<usize, String>(0)?,
                b64_content_nonce: row.get::<usize, String>(0)?,
                b64_notes_nonce: row.get::<usize, String>(0)?,
            })
        })?;
        let mut passwords = Vec::new();
        for b64password_result in rows {
            passwords.push(b64password_result?);
        }
        Ok(Some(passwords))
    }

    /// Add a [Base64Password] to the `passwords` database table.
    /// Return [Err] if that password name + owner username combination already exists.
    pub fn add_new_password(&mut self, password: Base64Password) -> rusqlite::Result<()> {
        self.connection
            .execute(INSERT_NEW_PASSWORD, password.as_tuple())?;
        Ok(())
    }

    /// Retrieve user account credentials from the database as a [Base64Account].
    /// Return [`Ok<None>`] if no account with that username exists.
    /// Return [Err] on a database error.
    pub fn get_b64_account(&self, username: &str) -> rusqlite::Result<Option<Base64Account>> {
        let mut statement = self.connection.prepare(GET_ACCOUNT)?;

        let account_result =
            statement.query_row([helpers::bytes_to_b64(username.as_bytes())], |row| {
                Ok(Base64Account {
                    b64_username: row.get::<usize, String>(0)?,
                    b64_password_salt: row.get::<usize, String>(1)?,
                    b64_dbl_hashed_password_hash: row.get::<usize, String>(2)?,
                    b64_dbl_hashed_password_salt: row.get::<usize, String>(3)?,
                    b64_encrypted_key_ciphertext: row.get::<usize, String>(4)?,
                    b64_encrypted_key_nonce: row.get::<usize, String>(5)?,
                })
            });

        match account_result {
            Ok(account) => Ok(Some(account)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Add a [Base64Account] to the `user_credentials` database table.
    /// Return [Err] if that account already exists.
    pub fn add_new_account(&mut self, account: Base64Account) -> rusqlite::Result<()> {
        self.connection
            .execute(INSERT_NEW_ACCOUNT, account.as_tuple())?;
        Ok(())
    }

    /// Delete the contents of the given table.
    /// Return [Err] if that table does not exist.
    pub fn truncate_table(&mut self, table_name: &str) -> rusqlite::Result<()> {
        self.connection
            .execute(&format!("DELETE FROM {}", table_name), ())?;
        Ok(())
    }

    // GETTERS

    /// Get the path at which this [Database] is located.
    pub fn get_path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::ErrorCode;

    #[test]
    fn test_dne() {
        let err = Database::connect("./not/a/real/path/test.db").unwrap_err();

        if let Some(ErrorCode::CannotOpen) = err.sqlite_error_code() {
        } else {
            dbg!(&err);
            panic!("Wrong error type");
        }
    }
}
