//! All saving, loading, and editing of `dgruft` data is handled through here.
use std::fs::remove_dir_all;

use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{self, eyre};

mod database;
mod database_traits;
mod filesystem;
mod sql_schemas;
mod sql_statements;

use super::{
    account::{Account, UnlockedAccount},
    credential::Credential,
    encryption::encrypted::{Aes256Key, TryFromEncrypted},
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

    // ACCOUNT FUNCTIONALITY

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
    pub fn delete_account<S>(&mut self, username: S) -> eyre::Result<()>
    where
        S: AsRef<str>,
    {
        // Get the path of this username's directory.
        let account_dir = get_account_file_dir(&self.filesystem_directory, username.as_ref())?;
        // Open a new database transaction.
        let tx = self.database.open_transaction()?;
        // Attempt to delete the account's database entry, cascading all of the account's files and
        // credentials.
        Database::transaction_delete::<Account, &str, 1>([username.as_ref()], &tx)?;
        // Attempt to delete the account's files directory.
        remove_dir_all(account_dir)?;
        // Commit the transaction to the database.
        Ok(tx.commit()?)
    }

    /// Load an [Account] with the given `username`.
    pub fn load_account<S>(&self, username: S) -> eyre::Result<Account>
    where
        S: AsRef<str>,
    {
        // Get the path of this username's directory.
        get_account_file_dir(&self.filesystem_directory, username.as_ref())?;
        // Get the account from the database.
        let loaded_account = self
            .database
            .select_entry_err_none::<Account, &str, 1>([username.as_ref()])?;
        Ok(loaded_account)
    }

    /// Load an [UnlockedAccount] with the given `username`.
    pub fn load_unlocked_account<S>(
        &self,
        username: S,
        password: S,
    ) -> eyre::Result<UnlockedAccount>
    where
        S: AsRef<str>,
    {
        // Load the account.
        let loaded_account = self.load_account(username.as_ref())?;
        // Unlock the account.
        loaded_account.unlock(password.as_ref())
    }

    // CREDENTIAL FUNCTIONALITY

    /// Create a new [Credential] & add it to the [Database].
    pub fn create_credential<S>(
        &mut self,
        owner_username: S,
        key: Aes256Key,
        name: S,
        username: S,
        password: S,
        notes: S,
    ) -> eyre::Result<()>
    where
        S: AsRef<str>,
    {
        // Create the credential.
        let credential = Credential::try_new(
            owner_username.as_ref(),
            key,
            name.as_ref(),
            username.as_ref(),
            password.as_ref(),
            notes.as_ref(),
        )?;
        // Verify that the credential will be unique.
        if self.load_credential(&owner_username, &name, key).is_ok() {
            return
                Err(
                    eyre!(
                        "Failed to create new credential: A credential named \"{}\" owned by account \"{}\" already exists.",
                        name.as_ref(),
                        owner_username.as_ref()
                        )
                    );
        }

        // Open a new database transaction.
        let tx = self.database.open_transaction()?;
        // Attempt to add a credential to the database.
        Database::transaction_insert(credential, &tx)?;
        // Commit the database transaction.
        Ok(tx.commit()?)
    }

    /// Delete a [Credential] from the [Database], rolling back the changes on failure.
    pub fn delete_credential<S>(
        &mut self,
        owner_username: S,
        name: S,
        key: Aes256Key,
    ) -> eyre::Result<()>
    where
        S: AsRef<str>,
    {
        // Find the credential to delete.
        let loaded_credential = self.load_credential(&owner_username, &name, key)?;
        // Open a new database transaction.
        let tx = self.database.open_transaction()?;
        // Delete the credential.
        Database::transaction_delete::<Credential, &[u8], 2>(
            [
                owner_username.as_ref().as_bytes(),
                loaded_credential.encrypted_name().cipherbytes(),
            ],
            &tx,
        )?;
        // Commit the database transaction.
        Ok(tx.commit()?)
    }

    /// Load the [Credential] with the given `owner_username` & `name`.
    pub fn load_credential<S>(
        &self,
        owner_username: S,
        name: S,
        key: Aes256Key,
    ) -> eyre::Result<Credential>
    where
        S: AsRef<str>,
    {
        // Get the credentials owned by this account.
        let owned_credentials = self.load_account_credentials(owner_username.as_ref())?;
        // Find the credential that matches the given name.
        for credential in owned_credentials {
            if credential.name::<String>(key)? == name.as_ref() {
                // Match found.
                return Ok(credential);
            }
        }
        Err(eyre!(
            "No credentials named \"{}\" are owned by account \"{}\".",
            name.as_ref(),
            owner_username.as_ref()
        ))
    }

    /// Load all [Credential] belonging to the given `owner_username`.
    pub fn load_account_credentials<S>(&self, owner_username: S) -> eyre::Result<Vec<Credential>>
    where
        S: AsRef<str>,
    {
        self.database
            .select_owned_entries::<Credential, &str, 1>([owner_username.as_ref()])
    }

    // FILE FUNCTIONALITY

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
        let fs_name = "create_del_accs";
        let db_path = db_path(db_name);
        let fs_dir = fs_dir(fs_name);
        refresh_test_db(db_name);
        refresh_test_fs(fs_name);

        let mut vault = Vault::connect(&db_path, &fs_dir).unwrap();

        let username1 = "mr_test";
        let password1 = "open sesame!";
        vault.create_new_account(username1, password1).unwrap();
        let _ = vault.create_new_account(username1, password1).unwrap_err();

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

    #[test]
    fn create_del_creds() {
        let db_name = "create_del_creds.db";
        let fs_name = "create_del_creds";
        let db_path = db_path(db_name);
        let fs_dir = fs_dir(fs_name);
        refresh_test_db(db_name);
        refresh_test_fs(fs_name);

        let mut vault = Vault::connect(&db_path, &fs_dir).unwrap();

        let username1 = "mr_test";
        let password1 = "open sesame!";
        vault.create_new_account(username1, password1).unwrap();
        let unlocked1 = vault.load_unlocked_account(username1, password1).unwrap();
        assert!(vault
            .load_account_credentials(username1)
            .unwrap()
            .is_empty());

        let username2 = "mr_awesome";
        let password2 = "let me in!!!!!!";
        vault.create_new_account(username2, password2).unwrap();
        let unlocked2 = vault.load_unlocked_account(username2, password2).unwrap();
        assert!(vault
            .load_account_credentials(username2)
            .unwrap()
            .is_empty());

        vault
            .create_credential(
                username1,
                unlocked1.key(),
                "my bank account",
                "1234 5678 9012 3456",
                "letmeinpls",
                "expiry date: 12/34",
            )
            .unwrap();

        assert_eq!(vault.load_account_credentials(username1).unwrap().len(), 1);
        assert!(vault
            .load_account_credentials(username2)
            .unwrap()
            .is_empty());

        let _ = vault
            .create_credential(
                username1,
                unlocked1.key(),
                "my bank account",
                "blahblahblah",
                "kjsahdkasd",
                "credential names must be unique!",
            )
            .unwrap_err();

        assert_eq!(vault.load_account_credentials(username1).unwrap().len(), 1);
        assert!(vault
            .load_account_credentials(username2)
            .unwrap()
            .is_empty());

        vault
            .create_credential(
                username1,
                unlocked1.key(),
                "Sploogle account",
                "notarealemail@sploogle.blahblahblah",
                "1234_i_love_sploogle_1234",
                "",
            )
            .unwrap();

        assert_eq!(vault.load_account_credentials(username1).unwrap().len(), 2);
        assert!(vault
            .load_account_credentials(username2)
            .unwrap()
            .is_empty());

        vault
            .create_credential(
                username2,
                unlocked2.key(),
                "my bank account",
                "0987 6543 2109 8765",
                "UnbreakablePassword!1234",
                "remember to change your password next Tuesday!",
            )
            .unwrap();

        assert_eq!(vault.load_account_credentials(username1).unwrap().len(), 2);
        assert_eq!(vault.load_account_credentials(username2).unwrap().len(), 1);

        // Wrong name.
        let _ = vault
            .delete_credential(username1, "Foogle account", unlocked1.key())
            .unwrap_err();
        // Wrong key.
        let _ = vault
            .delete_credential(username1, "Sploogle account", unlocked2.key())
            .unwrap_err();
        // Wrong account.
        let _ = vault
            .delete_credential(username2, "Sploogle account", unlocked1.key())
            .unwrap_err();
        vault
            .delete_credential(username1, "Sploogle account", unlocked1.key())
            .unwrap();

        let _ = vault
            .load_credential(username1, "Sploogle account", unlocked1.key())
            .unwrap_err();
        vault
            .load_credential(username1, "my bank account", unlocked1.key())
            .unwrap();
        vault
            .load_credential(username2, "my bank account", unlocked2.key())
            .unwrap();

        vault.delete_account(username2).unwrap();

        let _ = vault
            .load_credential(username2, "my bank account", unlocked2.key())
            .unwrap_err();
        vault
            .load_credential(username1, "my bank account", unlocked1.key())
            .unwrap();
    }
}
