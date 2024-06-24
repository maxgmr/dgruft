//! All functionality related to the [SQLite](https://www.sqlite.org/about.html) database dgruft uses for persistence.
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::usize;

use rusqlite::{config::DbConfig, Connection, OpenFlags};

use crate::{
    backend::{
        account::Base64Account, file::Base64FileData, password::Base64Password, sql_schemas::*,
        sql_statements::*,
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
        P: AsRef<Path> + AsRef<OsStr>,
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
        if let Ok(None) = self.get_b64_account(username) {
            return Ok(None);
        };

        let mut statement = self.connection.prepare(GET_USER_PASSWORDS)?;
        let rows = statement.query_map([helpers::bytes_to_b64(username.as_bytes())], |row| {
            Ok(Base64Password {
                b64_owner_username: row.get::<usize, String>(0)?,
                b64_name_ciphertext: row.get::<usize, String>(1)?,
                b64_username_ciphertext: row.get::<usize, String>(2)?,
                b64_content_ciphertext: row.get::<usize, String>(3)?,
                b64_notes_ciphertext: row.get::<usize, String>(4)?,
                b64_name_nonce: row.get::<usize, String>(5)?,
                b64_username_nonce: row.get::<usize, String>(6)?,
                b64_content_nonce: row.get::<usize, String>(7)?,
                b64_notes_nonce: row.get::<usize, String>(8)?,
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

    /// Delete a given account from the `user_credentials` database table.
    /// Matches the username of the account.
    /// Return [`Ok<None>`] if no account with that username exists.
    pub fn delete_account(&mut self, username: &str) -> rusqlite::Result<Option<()>> {
        let num_rows = self
            .connection
            .execute(DELETE_ACCOUNT, [helpers::bytes_to_b64(username.as_bytes())])?;
        if num_rows == 0 {
            Ok(None)
        } else {
            Ok(Some(()))
        }
    }

    /// Retrieve a user's files from the database as a [Vec] of [Base64FileData].
    /// Return [`Ok<None>`] if no account with that username exists.
    /// Return [Err] on a database error.
    pub fn get_b64_files(&self, username: &str) -> rusqlite::Result<Option<Vec<Base64FileData>>> {
        // Ensure account exists
        if let Ok(None) = self.get_b64_account(username) {
            return Ok(None);
        };

        let mut statement = self.connection.prepare(GET_USER_FILES)?;
        let rows = statement.query_map([helpers::bytes_to_b64(username.as_bytes())], |row| {
            Ok(Base64FileData {
                b64_path: row.get::<usize, String>(0)?,
                b64_name: row.get::<usize, String>(1)?,
                b64_owner_username: row.get::<usize, String>(2)?,
                b64_content_nonce: row.get::<usize, String>(3)?,
            })
        })?;
        let mut files = Vec::new();
        for b64file_result in rows {
            files.push(b64file_result?);
        }
        Ok(Some(files))
    }

    /// Retrieve file data from the database as a [Base64FileData].
    /// Return [`Ok<None>`] if no file with that path exists.
    /// Return [Err] on a database error.
    pub fn get_b64_file_data(&self, path_string: &str) -> rusqlite::Result<Option<Base64FileData>> {
        let mut statement = self.connection.prepare(GET_FILE)?;

        let file_data_result =
            statement.query_row([helpers::bytes_to_b64(path_string.as_bytes())], |row| {
                Ok(Base64FileData {
                    b64_path: row.get::<usize, String>(0)?,
                    b64_name: row.get::<usize, String>(1)?,
                    b64_owner_username: row.get::<usize, String>(2)?,
                    b64_content_nonce: row.get::<usize, String>(3)?,
                })
            });

        match file_data_result {
            Ok(file_data) => Ok(Some(file_data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Add [Base64FileData] to the `files` database table.
    /// Return [Err] if that file path already exists.
    pub fn add_new_file_data(&mut self, b64_file_data: Base64FileData) -> rusqlite::Result<()> {
        self.connection
            .execute(INSERT_NEW_FILE, b64_file_data.as_tuple())?;
        Ok(())
    }

    /// Delete a given account from the `files` database table.
    /// Matches the file path string of the account.
    /// Return [`Ok<None>`] if no file with that path exists.
    pub fn delete_file_data(&mut self, path_string: &str) -> rusqlite::Result<Option<()>> {
        let num_rows = self
            .connection
            .execute(DELETE_FILE, [helpers::bytes_to_b64(path_string.as_bytes())])?;
        if num_rows == 0 {
            Ok(None)
        } else {
            Ok(Some(()))
        }
    }

    /// Update the content nonce of a file on the database.
    /// Return [rusqlite::Error::QueryReturnedNoRows] and undoes the transaction iff not exactly
    /// one row would be changed.
    pub fn update_file_content_nonce(
        &mut self,
        new_nonce: &[u8; 12],
        path_string: &str,
    ) -> rusqlite::Result<()> {
        let tx = self.connection.transaction()?;
        let num_changed = tx.execute(
            UPDATE_FILE_CONTENT_NONCE,
            [
                helpers::bytes_to_b64(new_nonce),
                helpers::bytes_to_b64(path_string.as_bytes()),
            ],
        )?;
        if num_changed != 1 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        tx.commit()?;
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
    pub fn path(&self) -> &Path {
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
