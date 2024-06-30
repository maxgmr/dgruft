//! All saving, loading, and editing of `dgruft` data is handled through here.
use std::fs;

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
    encryption::encrypted::{
        Aes256Key, Aes256Nonce, Encrypted, TryFromEncrypted, TryIntoEncrypted,
    },
    file_data::FileData,
    hashing::hashed::{Hash, Salt},
};
use database::Database;
use database_traits::{AccountUpdateField, CredentialUpdateField, FileDataUpdateField};
use filesystem::{
    get_account_file_dir, get_file_path, new_account_file_dir, new_file, open_file,
    read_file_bytes, verify_writeable_dir, write_file,
};

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
        fs::remove_dir_all(account_dir)?;
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

    /// Change the password of an [Account].
    pub fn change_account_password<S>(
        &mut self,
        username: S,
        old_password: S,
        new_password: S,
    ) -> eyre::Result<()>
    where
        S: AsRef<str>,
    {
        // Load & unlock the account.
        let mut unlocked_account =
            self.load_unlocked_account(username.as_ref(), old_password.as_ref())?;
        // Change unlocked account's password.
        unlocked_account.change_password(new_password.as_ref())?;

        // Open a new database transaction.
        let tx = self.database.open_transaction()?;
        // Update the password salt.
        let num_rows = Database::transaction_update::<Account, &str, Salt<64>, 1, 1>(
            [username.as_ref()],
            AccountUpdateField::PasswordSalt,
            [*unlocked_account.hashed_password().salt()],
            &tx,
        )?;
        Self::validate_one_row(num_rows)?;
        // Update the double-hashed password hash.
        let num_rows = Database::transaction_update::<Account, &str, Hash<32>, 1, 1>(
            [username.as_ref()],
            AccountUpdateField::DblHashedPasswordHash,
            [*unlocked_account.dbl_hashed_password().hash()],
            &tx,
        )?;
        Self::validate_one_row(num_rows)?;
        // Update the double-hashed password salt.
        let num_rows = Database::transaction_update::<Account, &str, Salt<64>, 1, 1>(
            [username.as_ref()],
            AccountUpdateField::DblHashedPasswordSalt,
            [*unlocked_account.dbl_hashed_password().salt()],
            &tx,
        )?;
        Self::validate_one_row(num_rows)?;
        // Update the encrypted key cipherbytes.
        let num_rows = Database::transaction_update::<Account, &str, &[u8], 1, 1>(
            [username.as_ref()],
            AccountUpdateField::EncryptedKeyCipherbytes,
            [unlocked_account.encrypted_key().cipherbytes()],
            &tx,
        )?;
        Self::validate_one_row(num_rows)?;
        // Update the encrypted key nonce.
        let num_rows = Database::transaction_update::<Account, &str, Aes256Nonce, 1, 1>(
            [username.as_ref()],
            AccountUpdateField::EncryptedKeyNonce,
            [unlocked_account.encrypted_key().nonce()],
            &tx,
        )?;
        Self::validate_one_row(num_rows)?;
        // Commit the database transaction.
        Ok(tx.commit()?)
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
            .select_owned_entries([owner_username.as_ref()])
    }

    /// Update a [Credential]'s field.
    pub fn update_credential<S>(
        &mut self,
        owner_username: S,
        name: S,
        key: Aes256Key,
        cipherbytes_field: CredentialUpdateField,
        nonce_field: CredentialUpdateField,
        new_value: S,
    ) -> eyre::Result<()>
    where
        S: AsRef<str>,
    {
        // Load the credential.
        let credential = self.load_credential(owner_username.as_ref(), name.as_ref(), key)?;
        // Get the primary key of the credential.
        let primary_key = [
            owner_username.as_ref().as_bytes(),
            credential.encrypted_name().cipherbytes(),
        ];
        // Encrypt the new value.
        let encrypted_new_value = new_value.as_ref().try_encrypt_with_key(key)?;
        // Open a new transaction.
        let tx = self.database.open_transaction()?;
        // Update the field's cipherbytes.
        let num_rows = Database::transaction_update::<Credential, &[u8], &[u8], 2, 1>(
            primary_key,
            cipherbytes_field,
            [encrypted_new_value.cipherbytes()],
            &tx,
        )?;
        Self::validate_one_row(num_rows)?;
        // Update the field's nonce.
        let num_rows = Database::transaction_update::<Credential, &[u8], Aes256Nonce, 2, 1>(
            primary_key,
            nonce_field,
            [encrypted_new_value.nonce()],
            &tx,
        )?;
        Self::validate_one_row(num_rows)?;
        // Commit the transaction.
        Ok(tx.commit()?)
    }

    // FILE FUNCTIONALITY

    /// Create a new file, along with its corresponding [FileData], & add it to the [Database].
    pub fn create_file<S, E>(
        &mut self,
        filename: S,
        owner_username: S,
        contents: E,
        key: Aes256Key,
    ) -> eyre::Result<()>
    where
        S: AsRef<str>,
        E: TryIntoEncrypted,
    {
        // Get the future path of this file.
        let file_path = get_file_path(&self.filesystem_directory, &owner_username, &filename)?;

        // Encrypt the contents of the new file.
        let encrypted_contents = contents.try_encrypt_with_key(key)?;

        // Create the file data.
        let file_data = FileData::new(
            &file_path,
            filename.as_ref().to_owned(),
            owner_username.as_ref().to_owned(),
            encrypted_contents.nonce().to_owned(),
        );

        // Open a new database transaction.
        let tx = self.database.open_transaction()?;
        // Attempt to add the file data to the database.
        Database::transaction_insert(file_data, &tx)?;
        // Attempt to create a new file with the encrypted contents.
        new_file(file_path, encrypted_contents.cipherbytes())?;
        // Commit the transaction.
        Ok(tx.commit()?)
    }

    /// Delete a file and its corresponding [FileData] from the [Database], rolling back the
    /// changes on a failure.
    pub fn delete_file<S>(&mut self, username: S, filename: S) -> eyre::Result<()>
    where
        S: AsRef<str>,
    {
        // Get the file path.
        let file_path = get_file_path(&self.filesystem_directory, &username, &filename)?;
        // Open a new database transaction.
        let tx = self.database.open_transaction()?;
        // Delete the file data entry.
        Database::transaction_delete::<FileData, &Utf8Path, 1>([&file_path], &tx)?;
        // Delete the file.
        fs::remove_file(&file_path)?;
        // Commit the database transaction.
        Ok(tx.commit()?)
    }

    /// Load the file and [FileData] with the given `owner_username` & `filename`.
    pub fn load_file<S, E>(
        &self,
        username: S,
        filename: S,
        key: Aes256Key,
    ) -> eyre::Result<(FileData, E)>
    where
        S: AsRef<str>,
        E: TryFromEncrypted,
    {
        // Get the file path.
        let file_path = get_file_path(&self.filesystem_directory, &username, &filename)?;
        // Load the file data.
        let file_data: FileData = self.database.select_entry_err_none([&file_path])?;
        // Load the encrypted file contents.
        let file = open_file(&file_path)?;
        let encrypted_file_bytes = read_file_bytes(&file)?;
        let encrypted_file =
            Encrypted::from_fields(encrypted_file_bytes, file_data.contents_nonce());
        // Decrypt and load the file contents.
        let decrypted_contents: E = E::try_decrypt(&encrypted_file, key)?;

        Ok((file_data, decrypted_contents))
    }

    /// Load all [FileData] belonging to the given `owner_username`.
    pub fn load_account_files_data<S>(&self, owner_username: S) -> eyre::Result<Vec<FileData>>
    where
        S: AsRef<str>,
    {
        self.database
            .select_owned_entries([owner_username.as_ref()])
    }

    /// Update a file's content.
    pub fn update_file<S, B>(
        &mut self,
        username: S,
        filename: S,
        key: Aes256Key,
        new_file_contents: B,
    ) -> eyre::Result<()>
    where
        S: AsRef<str>,
        B: AsRef<[u8]>,
    {
        // Get the file path.
        let file_path = get_file_path(&self.filesystem_directory, &username, &filename)?;
        // Encrypt the new file contents.
        let encrypted_contents = new_file_contents.as_ref().try_encrypt_with_key(key)?;
        // Open a new transaction.
        let tx = self.database.open_transaction()?;
        // Update the file data contents nonce.
        let num_rows = Database::transaction_update::<FileData, &Utf8Path, Aes256Nonce, 1, 1>(
            [&file_path],
            FileDataUpdateField::ContentsNonce,
            [encrypted_contents.nonce()],
            &tx,
        )?;
        Self::validate_one_row(num_rows)?;
        // Write the cipherbytes to the file.
        write_file(&file_path, encrypted_contents.cipherbytes())?;
        // Commit the transaction.
        Ok(tx.commit()?)
    }
    // Helper function: Ensure that exactly one row was updated.
    fn validate_one_row(num_rows: usize) -> eyre::Result<()> {
        match num_rows {
            1 => Ok(()),
            num => Err(eyre!(
                "Tried to update 1 row; {num} matches found. No changes to database were made."
            )),
        }
    }
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

    #[test]
    fn create_del_files() {
        let db_name = "create_del_files.db";
        let fs_name = "create_del_files";
        let db_path = db_path(db_name);
        let fs_dir = fs_dir(fs_name);
        refresh_test_db(db_name);
        refresh_test_fs(fs_name);

        let mut vault = Vault::connect(&db_path, &fs_dir).unwrap();

        let username1 = "mr_test";
        let password1 = "open sesame!";
        vault.create_new_account(username1, password1).unwrap();
        let unlocked1 = vault.load_unlocked_account(username1, password1).unwrap();
        assert!(vault.load_account_files_data(username1).unwrap().is_empty());

        let username2 = "mr_awesome";
        let password2 = "let me in!!!!!!";
        vault.create_new_account(username2, password2).unwrap();
        let unlocked2 = vault.load_unlocked_account(username2, password2).unwrap();
        assert!(vault.load_account_files_data(username2).unwrap().is_empty());

        // Add some files.
        vault
            .create_file(
                "shopping list",
                "mr_test",
                "eggs\nmilk\nbread",
                unlocked1.key(),
            )
            .unwrap();
        vault
            .create_file(
                "my secret",
                "mr_test",
                "Sometimes even I, the great Mr. Test, get tired of tests sometimes...",
                unlocked1.key(),
            )
            .unwrap();
        let _ = vault
            .create_file("my secret", "mr_test", "No dupes allowed!", unlocked1.key())
            .unwrap_err();

        vault.create_file(
            "my secret", 
            "mr_awesome", 
            "i wish i wasn't the second account ALL the time...\n\nsometimes a guy just wants to be \"number one\", yennow?",
            unlocked2.key()
            ).unwrap();
        vault
            .create_file("中文", "mr_awesome", "加拿大很美丽", unlocked2.key())
            .unwrap();
        vault
            .create_file("blah blah blah", "mr_awesome", "", unlocked2.key())
            .unwrap();

        // Open some files.
        assert_eq!(vault.load_account_files_data("mr_test").unwrap().len(), 2);
        assert_eq!(
            vault.load_account_files_data("mr_awesome").unwrap().len(),
            3
        );

        let (test_shop_fd, test_shop_contents): (FileData, String) = vault
            .load_file("mr_test", "shopping list", unlocked1.key())
            .unwrap();
        assert_eq!(test_shop_fd.filename(), "shopping list");
        assert_eq!(test_shop_contents, "eggs\nmilk\nbread");

        let (test_secret_fd, test_secret_contents): (FileData, String) = vault
            .load_file("mr_test", "my secret", unlocked1.key())
            .unwrap();
        assert_eq!(test_secret_fd.filename(), "my secret");
        assert_eq!(
            test_secret_contents,
            "Sometimes even I, the great Mr. Test, get tired of tests sometimes..."
        );

        let (awesome_secret_fd, awesome_secret_contents): (FileData, String) = vault
            .load_file("mr_awesome", "my secret", unlocked2.key())
            .unwrap();
        assert_eq!(awesome_secret_fd.filename(), "my secret");
        assert_eq!(
            awesome_secret_contents,
            "i wish i wasn't the second account ALL the time...\n\nsometimes a guy just wants to be \"number one\", yennow?"
        );

        let (awesome_zhongwen_fd, awesome_zhongwen_contents): (FileData, String) = vault
            .load_file("mr_awesome", "中文", unlocked2.key())
            .unwrap();
        assert_eq!(awesome_zhongwen_fd.filename(), "中文");
        assert_eq!(awesome_zhongwen_contents, "加拿大很美丽");

        // Ensure that the file will not be deleted on database error.
        // Force delete database entry improperly to cause error.
        let zhongwen_path =
            get_file_path(&vault.filesystem_directory, "mr_awesome", "中文").unwrap();
        vault
            .database
            .delete_entry::<FileData, &Utf8Path, 1>([&zhongwen_path])
            .unwrap();
        let _ = vault.delete_file("mr_awesome", "中文").unwrap_err();
        open_file(zhongwen_path).unwrap();
        assert_eq!(
            vault.load_account_files_data("mr_awesome").unwrap().len(),
            2
        );

        // Ensure that database entry will not be deleted on file error.
        // Force delete file to ensure file error.
        let blah_path =
            get_file_path(&vault.filesystem_directory, "mr_awesome", "blah blah blah").unwrap();
        fs::remove_file(&blah_path).unwrap();
        let _ = vault
            .delete_file("mr_awesome", "blah blah blah")
            .unwrap_err();
        let _ = vault
            .load_file::<&str, Vec<u8>>("mr_awesome", "blah blah blah", unlocked2.key())
            .unwrap_err();
        assert_eq!(
            vault.load_account_files_data("mr_awesome").unwrap().len(),
            2
        );
    }

    #[test]
    fn change_password() {
        let db_name = "change_password.db";
        let fs_name = "change_password";
        let db_path = db_path(db_name);
        let fs_dir = fs_dir(fs_name);
        refresh_test_db(db_name);
        refresh_test_fs(fs_name);

        let mut vault = Vault::connect(&db_path, &fs_dir).unwrap();

        let username = "mr_test";
        let password = "open sesame!";
        let new_password = "mr. test is the best!";
        vault.create_new_account(username, password).unwrap();
        let key = vault
            .load_unlocked_account(username, password)
            .unwrap()
            .key();

        let filename = "f";
        let contents = "blah blah blah. this is a test. 我要茶";
        vault
            .create_file(filename, username, contents, key)
            .unwrap();
        let (_, fcontents): (_, String) = vault.load_file(username, filename, key).unwrap();
        assert_eq!(fcontents, contents);

        vault
            .change_account_password(username, password, new_password)
            .unwrap();

        let _ = vault.load_unlocked_account(username, password).unwrap_err();
        let key = vault
            .load_unlocked_account(username, new_password)
            .unwrap()
            .key();
        let (_, fcontents): (_, String) = vault.load_file(username, filename, key).unwrap();
        assert_eq!(fcontents, contents);
    }

    #[test]
    fn update_credential() {
        let db_name = "update_credential.db";
        let fs_name = "update_credential";
        let db_path = db_path(db_name);
        let fs_dir = fs_dir(fs_name);
        refresh_test_db(db_name);
        refresh_test_fs(fs_name);

        let mut vault = Vault::connect(&db_path, &fs_dir).unwrap();

        let username = "mr_test";
        let password = "open sesame!";
        vault.create_new_account(username, password).unwrap();
        let key = vault
            .load_unlocked_account(username, password)
            .unwrap()
            .key();

        let c_name = "c1";
        let c_username = "my_account";
        let c_password = "my_password";
        let c_notes = "my_notes";

        vault
            .create_credential(username, key, c_name, c_username, c_password, c_notes)
            .unwrap();
        let loaded_c = vault.load_credential(username, c_name, key).unwrap();
        assert_eq!(loaded_c.username::<String>(key).unwrap(), c_username);

        let new_c_username = "my_new_account";

        vault
            .update_credential(
                username,
                c_name,
                key,
                CredentialUpdateField::EncryptedUsernameCipherbytes,
                CredentialUpdateField::EncryptedUsernameNonce,
                new_c_username,
            )
            .unwrap();
        let loaded_c = vault.load_credential(username, c_name, key).unwrap();
        assert_eq!(loaded_c.username::<String>(key).unwrap(), new_c_username);

        let new_c_password = "my_new_password";

        vault
            .update_credential(
                username,
                c_name,
                key,
                CredentialUpdateField::EncryptedPasswordCipherbytes,
                CredentialUpdateField::EncryptedPasswordNonce,
                new_c_password,
            )
            .unwrap();
        let loaded_c = vault.load_credential(username, c_name, key).unwrap();
        assert_eq!(loaded_c.password::<String>(key).unwrap(), new_c_password);

        let new_c_notes = "my_new_notes";

        vault
            .update_credential(
                username,
                c_name,
                key,
                CredentialUpdateField::EncryptedNotesCipherbytes,
                CredentialUpdateField::EncryptedNotesNonce,
                new_c_notes,
            )
            .unwrap();
        let loaded_c = vault.load_credential(username, c_name, key).unwrap();
        assert_eq!(loaded_c.notes::<String>(key).unwrap(), new_c_notes);
    }

    #[test]
    fn update_file() {
        let db_name = "update_file.db";
        let fs_name = "update_file";
        let db_path = db_path(db_name);
        let fs_dir = fs_dir(fs_name);
        refresh_test_db(db_name);
        refresh_test_fs(fs_name);

        let mut vault = Vault::connect(&db_path, &fs_dir).unwrap();

        let username = "mr_test";
        let password = "open sesame!";
        vault.create_new_account(username, password).unwrap();
        let key = vault
            .load_unlocked_account(username, password)
            .unwrap()
            .key();

        let filename = "f";
        let old_contents = "this is a test.";
        vault
            .create_file(filename, username, old_contents, key)
            .unwrap();
        let (loaded_file_data, decrypted_contents): (FileData, String) =
            vault.load_file(username, filename, key).unwrap();
        assert_eq!(loaded_file_data.filename(), filename);
        assert_eq!(decrypted_contents, old_contents);

        let new_contents = "this is a test, i sure hope it works!";
        vault
            .update_file(username, filename, key, new_contents)
            .unwrap();

        let (loaded_file_data, decrypted_contents): (FileData, String) =
            vault.load_file(username, filename, key).unwrap();
        assert_eq!(loaded_file_data.filename(), filename);
        assert_eq!(decrypted_contents, new_contents);
    }
}
