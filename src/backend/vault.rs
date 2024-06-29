//! All saving, loading, and editing of `dgruft` data is handled through here.
use std::fs::remove_dir_all;

use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{self};

mod database;
mod database_traits;
mod filesystem;
mod sql_schemas;
mod sql_statements;

use super::{
    account::{Account, UnlockedAccount},
    credential::Credential,
    file_data::FileData,
};
use database::Database;
use filesystem::{get_account_file_dir, new_account_file_dir, verify_writeable_dir};

/// The [Vault] is reponsible for all saving, loading, and editing of `dgruft` data. It handles the
/// [Database] and the filesystem together to ensure that the two remain consistent when interacted
/// with by other code.
#[derive(Debug)]
pub struct Vault {
    database: Database,
    filesystem_directory: Utf8PathBuf,
}
impl Vault {
    /// Connect to this [Vault]. For async programs, only one [Vault] should be loaded at a time.
    pub fn connect<P>(database_path: P, filesystem_directory: P) -> eyre::Result<Self>
    where
        P: AsRef<Utf8Path>,
    {
        // Ensure the filesystem directory is a valid directory with write permissions.
        verify_writeable_dir(&filesystem_directory)?;

        // Connect to the database.
        let database = Database::connect(database_path.as_ref())?;

        Ok(Self {
            database,
            filesystem_directory: filesystem_directory.as_ref().into(),
        })
    }

    /// Create a new [Account] & add it to the [Database].
    pub fn create_new_account<S>(&mut self, username: S, password: S) -> eyre::Result<()>
    where
        S: AsRef<str>,
    {
        // Create a new account.
        let account = Account::new(username.as_ref(), password.as_ref())?;
        // Open a new database transaction.
        let tx = self.database.open_transaction()?;
        // Attempt to add the account to the database.
        Database::transaction_insert(account, &tx)?;
        // Attempt to create the account's files directory.
        new_account_file_dir(&self.filesystem_directory, username.as_ref())?;
        // Commit the transaction to the database.
        Ok(tx.commit()?)
    }

    /// Delete an [Account] from the [Database], rolling back the changes on failure.
    pub fn delete_account(&mut self, username: &str) -> eyre::Result<()> {
        // Get the path of this username's directory.
        let account_dir = get_account_file_dir(&self.filesystem_directory, username)?;
        // Open a new database transaction.
        let tx = self.database.open_transaction()?;
        // Attempt to delete the account's database entry, cascading all of the account's files and
        // credentials.
        Database::transaction_delete::<Account, &str, 1>([username], &tx)?;
        // Attempt to delete the account's files directory.
        remove_dir_all(account_dir)?;
        // Commit the transaction to the database.
        Ok(tx.commit()?)
    }

    /// Load an [Account] with the given `username`.
    pub fn load_account(&self, username: &str) -> eyre::Result<Account> {
        // Get the path of this username's directory.
        get_account_file_dir(&self.filesystem_directory, username)?;
        // Get the account from the database.
        let loaded_account = self
            .database
            .select_entry_err_none::<Account, &str, 1>([username])?;
        Ok(loaded_account)
    }

    /// Load an [UnlockedAccount] with the given `username`.
    pub fn load_unlocked_account(
        &self,
        username: &str,
        password: &str,
    ) -> eyre::Result<UnlockedAccount> {
        // Load the account.
        let loaded_account = self.load_account(username)?;
        // Unlock the account.
        loaded_account.unlock(password)
    }

    // /// Create a new file, along with [FileData], & add it to the [Database].
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use std::fs;

    use super::*;

    const TEST_DIR_STR: &str = "tests/test_vault_dir";

    fn test_dir() -> Utf8PathBuf {
        Utf8PathBuf::from(TEST_DIR_STR)
    }

    fn db_path(db_name: &str) -> Utf8PathBuf {
        let mut db_path = test_dir();
        db_path.push(db_name);
        db_path
    }

    fn fs_dir(fs_name: &str) -> Utf8PathBuf {
        let mut fs_dir = test_dir();
        fs_dir.push(fs_name);
        fs_dir
    }

    fn refresh_test_db(db_name: &str) {
        let _ = fs::remove_file(db_path(db_name));
        fs::File::create_new(db_path(db_name)).unwrap();
    }

    fn refresh_test_fs(fs_name: &str) {
        let _ = fs::remove_dir_all(fs_dir(fs_name));
        fs::create_dir(fs_dir(fs_name)).unwrap();
    }

    #[test]
    fn connect_ok() {
        let db_name = "connect_ok.db";
        let fs_name = "connect_ok";
        let db_path = db_path(db_name);
        let fs_dir = fs_dir(fs_name);
        refresh_test_db(db_name);
        refresh_test_fs(fs_name);
        Vault::connect(db_path, fs_dir).unwrap();
    }

    #[test]
    fn connect_non_dir() {
        let db_name = "connect_non_dir.db";
        let fs_name = "connect_non_dir";
        let db_path = db_path(db_name);
        refresh_test_db(db_name);
        refresh_test_fs(fs_name);
        let _ = Vault::connect(db_path, "src/backend/vault.rs".into()).unwrap_err();
    }

    #[test]
    fn create_del_accs() {
        let db_name = "create_del_accs.db";
        let fs_name = "connect_non_dir";
        let db_path = db_path(db_name);
        let fs_dir = fs_dir(fs_name);
        refresh_test_db(db_name);
        refresh_test_fs(fs_name);

        let mut vault = Vault::connect(&db_path, &fs_dir).unwrap();

        let username1 = "mr_test";
        let password1 = "open sesame!";
        vault.create_new_account(username1, password1).unwrap();

        let username2 = "mr_awesome";
        let password2 = "let me in!!!!!!";
        vault.create_new_account(username2, password2).unwrap();

        let _ = vault.create_new_account(username1, password2).unwrap_err();

        let loaded_acc1 = vault.load_account(username1).unwrap();
        assert_eq!(loaded_acc1.username(), username1);

        let unlocked_acc1 = vault.load_unlocked_account(username1, password1).unwrap();
        let _ = vault
            .load_unlocked_account(username1, "wrong password")
            .unwrap_err();

        assert_eq!(unlocked_acc1.password(), password1);

        let mut dir1 = fs_dir.clone();
        dir1.push(username1);

        let mut dir2 = fs_dir.clone();
        dir2.push(username2);

        let mut bad_dir = fs_dir.clone();
        bad_dir.push("mistah_doesnt_exist");

        fs::metadata(&dir1).unwrap();
        fs::metadata(&dir2).unwrap();

        let _ = vault.delete_account("mistah_doesnt_exist").unwrap_err();

        vault.delete_account(username1).unwrap();
        let _ = vault.delete_account(username1).unwrap_err();

        let _ = vault.load_account(username1).unwrap_err();
        vault.load_account(username2).unwrap();

        fs::metadata(&dir1).unwrap_err();
        fs::metadata(&dir2).unwrap();
    }
}
