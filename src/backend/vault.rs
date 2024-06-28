//! All saving, loading, and editing of `dgruft` data is handled through here.
use std::fs;

use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{self, eyre};

mod database;
mod database_traits;
mod filesystem;
mod sql_schemas;
mod sql_statements;

use super::account::Account;
use super::credential::Credential;
use super::file_data::FileData;
use database::{Database, Table};

/// The [Vault] is reponsible for all saving, loading, and editing of `dgruft` data. It handles the
/// [Database] and the filesystem together to ensure that the two remain consistent when interacted
/// with by other code.
#[derive(Debug)]
pub struct Vault {
    database: Database,
    filesystem_path: Utf8PathBuf,
}
impl Vault {
    /// Connect to this [Vault]. For async programs, only one [Vault] should be loaded at a time.
    pub fn connect<P>(database_path: P, filesystem_path: P) -> eyre::Result<Self>
    where
        P: AsRef<Utf8Path>,
    {
        // Check that `filesystem_path` is valid and is a directory.
        let metadata = fs::metadata(filesystem_path.as_ref())?;
        if !metadata.is_dir() {
            return Err(eyre!(
                "Failed to connect to Vault: {:?} is not a directory.",
                filesystem_path.as_ref()
            ));
        }

        // Ensure that the filesystem is not read-only.
        let filesystem_permissions = metadata.permissions();
        if filesystem_permissions.readonly() {
            return Err(eyre!(
                "Failed to connect to Vault: {:?} is read-only.",
                filesystem_path.as_ref()
            ));
        }

        // Connect to the database.
        let database = Database::connect(database_path.as_ref())?;

        Ok(Self {
            database,
            filesystem_path: filesystem_path.as_ref().into(),
        })
    }

    // /// Create a new [Account] & add it to the [Database].
    // pub fn create_new_account<S>(&self, username: S, password: S) -> eyre::Result<()>
    // where
    //     S: AsRef<str>,
    // {
    //     // Create account.
    //     let account = Account::new(username.as_ref(), password.as_ref())?;
    // }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    const TEST_DB_PATH_STR: &str = "tests/test_vault_dir/test-vault-db.db";
    const TEST_FS_DIR_STR: &str = "tests/test_vault_dir";

    fn test_db_path() -> Utf8PathBuf {
        Utf8PathBuf::from(TEST_DB_PATH_STR)
    }

    fn test_fs_dir() -> Utf8PathBuf {
        Utf8PathBuf::from(TEST_FS_DIR_STR)
    }

    fn refresh_test_db() {
        let _ = fs::remove_file(test_db_path());
        fs::File::create_new(test_db_path()).unwrap();
    }

    #[test]
    fn connect_ok() {
        refresh_test_db();
        Vault::connect(test_db_path(), test_fs_dir()).unwrap();
    }

    #[test]
    fn connect_non_dir() {
        refresh_test_db();
        let _ = Vault::connect(test_db_path(), "src/backend/vault.rs".into()).unwrap_err();
    }
}
