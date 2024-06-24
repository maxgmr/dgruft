//! Backend API.
use std::{
    ffi::OsString,
    fs::{self, create_dir, remove_dir_all},
    io::{self, Write},
    path::PathBuf,
};

use color_eyre::eyre::{self, eyre};
use file::FileData;

pub mod account;
pub mod database;
pub mod encrypted;
pub mod file;
pub mod hashed;
pub mod password;
mod sql_schemas;
mod sql_statements;

use crate::{error::Error, helpers};
use account::{Account, SecureFields};
use database::Database;
use password::Password;

const DATABASE_NAME: &str = "dgruft.db";

fn database_path() -> PathBuf {
    let mut path = helpers::get_data_dir();
    path.push(DATABASE_NAME);
    path
}

fn acc_path(username: &str) -> PathBuf {
    let mut path = helpers::get_data_dir();
    path.push(username);
    path
}

fn load_db() -> eyre::Result<Database> {
    Ok(Database::connect(database_path())?)
}

fn login(db: &mut Database, username: &str, password: &str) -> eyre::Result<SecureFields> {
    if let Some(b64account) = db.get_b64_account(username)? {
        let db_entry = Account::from_b64(b64account)?;
        Ok(db_entry.unlock(password)?)
    } else {
        Err(Error::AccountNotFoundError(username.to_owned()).into())
    }
}

/// Create a new account and store it in the database.
pub fn new_account(username: String, password: String) -> eyre::Result<()> {
    let confirm_password =
        rpassword::prompt_password(format!("Confirm Password for {}: ", username))?;
    if confirm_password != password {
        return Err(eyre!("Passwords for new account do not match."));
    }

    let mut db = load_db()?;

    // Create Account.
    let account = Account::new(&username, &password)?;

    // Add to database.
    db.add_new_account(account.to_b64())?;

    // Create the directory where this account's files will be stored.
    let acc_dir = acc_path(&username);
    create_dir(acc_dir)?;
    println!("Account \"{username}\" created successfully.");
    Ok(())
}

/// Delete an existing account and all its files and passwords.
pub fn delete_account(username: String, password: String, force: bool) -> eyre::Result<()> {
    let mut db = load_db()?;

    // Ensure account exists.
    let unlocked_account = login(&mut db, &username, &password)?;

    // Get all files & passwords of this account.
    let files = get_files(unlocked_account.username())?;
    let passwords = get_passwords(unlocked_account.username())?;

    // CLI confirm deletion if not forced.
    if !force {
        print!(
            "Really delete account \"{}\" with {} file(s) and {} password(s)? [y/N] ",
            unlocked_account.username(),
            files.len(),
            passwords.len()
        );
        let mut input = String::new();
        io::stdout().flush()?;
        io::stdin().read_line(&mut input)?;
        match input.to_lowercase().chars().next() {
            Some('y') => {}
            _ => {
                println!("File deletion cancelled.");
                return Ok(());
            }
        }
    }

    // Delete this account's database entry.
    if db.delete_account(&username)?.is_none() {
        return Err(Error::AccountNotFoundError(username).into());
    }

    // Delete the directory where this account's files were stored.
    // Restore database entry on failure.
    let acc_dir = acc_path(&username);
    if let Err(err) = remove_dir_all(acc_dir) {
        // Undo database changes.
        for file in files {
            db.add_new_file_data(file.to_b64()?)?;
        }
        for password in passwords {
            db.add_new_password(password.to_b64())?;
        }
        return Err(err.into());
    }

    println!("Account {username} deleted successfully.");
    Ok(())
}

/// Create a new file, add its data to the database, and store it in the user directory.
pub fn new_file(username: String, password: String, filename: OsString) -> eyre::Result<()> {
    // Load account entry from db.
    let mut db = load_db()?;
    let unlocked_account = login(&mut db, &username, &password)?;

    // Get user directory.
    let mut file_path = acc_path(&username);
    file_path.push(&filename);

    // Create new file.
    let file_data = FileData::new_with_key(
        unlocked_account.username(),
        unlocked_account.key(),
        filename,
        &file_path,
    )?;

    // Add to database— if err then undo file creation.
    if let Err(err) = db.add_new_file_data(file_data.to_b64()?) {
        // Undo change to disk.
        fs::remove_file(&file_path)?;
        return Err(err.into());
    }

    println!("File {:?} created successfully.", file_data.name());
    Ok(())
}

/// Decrypt and edit an existing file.
pub fn edit_file(username: String, password: String, filename: OsString) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// Delete a file from the user directory and database.
pub fn delete_file(
    username: String,
    password: String,
    filename: OsString,
    force: bool,
) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// Decrypt and list the names of this account's files.
pub fn list_files(username: String, password: String) -> eyre::Result<()> {
    // Load account entry from db.
    let mut db = load_db()?;
    let unlocked_account = login(&mut db, &username, &password)?;

    // Load list of files.
    let file_results =
        if let Some(b64_files_data) = db.get_b64_files(unlocked_account.username())? {
            b64_files_data.into_iter().map(FileData::from_b64)
        } else {
            return Err(Error::AccountNotFoundError(unlocked_account.username().to_owned()).into());
        };

    let mut files: Vec<String> = vec![];
    for file_result in file_results {
        files.push(
            file_result?
                .path()
                .to_owned()
                .into_os_string()
                .into_string()
                .unwrap(),
        );
    }

    println!("{}", files.join("\n"));

    Ok(())
}

/// Decrypt and get this account's files.
fn get_files(username: &str) -> eyre::Result<Vec<FileData>> {
    let db = load_db()?;

    // Load list of files.
    let file_results = if let Some(b64_files_data) = db.get_b64_files(username)? {
        b64_files_data.into_iter().map(FileData::from_b64)
    } else {
        return Err(Error::AccountNotFoundError(username.to_owned()).into());
    };

    let mut files: Vec<FileData> = vec![];
    for file_result in file_results {
        files.push(file_result?);
    }

    Ok(files)
}

/// Create a new password in the database.
pub fn new_password(
    username: String,
    password: String,
    passwordname: OsString,
) -> eyre::Result<()> {
    // TODO
    // Load account entry from db.
    let mut db = load_db()?;
    let unlocked_account = login(&mut db, &username, &password)?;

    // Create new password.

    // Add to database.

    println!("Password {passwordname:?} created successfully.");
    Ok(())
}

/// Decrypt and edit an existing password.
pub fn edit_password(username: String, password: String, filename: OsString) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// Delete a password from the user directory and database.
pub fn delete_password(
    username: String,
    password: String,
    passwordname: OsString,
    force: bool,
) -> eyre::Result<()> {
    // TODO
    Ok(())
}
/// Decrypt and list the names of this account's passwords.
pub fn list_passwords(username: String, password: String) -> eyre::Result<()> {
    // Load account entry from db.
    let mut db = load_db()?;
    let unlocked_account = login(&mut db, &username, &password)?;

    // Load list of passwords.
    let password_results =
        if let Some(b64_passwords) = db.get_b64_passwords(unlocked_account.username())? {
            b64_passwords.into_iter().map(Password::from_b64)
        } else {
            return Err(Error::AccountNotFoundError(unlocked_account.username().to_owned()).into());
        };

    let mut passwords: Vec<String> = vec![];
    for password_result in password_results {
        passwords.push(helpers::bytes_to_utf8(
            &password_result?
                .encrypted_name()
                .decrypt(unlocked_account.key())?,
            "password",
        )?);
    }

    println!("{}", passwords.join("\n"));

    Ok(())
}

/// Get the given account's passwords.
fn get_passwords(username: &str) -> eyre::Result<Vec<Password>> {
    let db = load_db()?;

    // Load list of passwords.
    let password_results = if let Some(b64_passwords) = db.get_b64_passwords(username)? {
        b64_passwords.into_iter().map(Password::from_b64)
    } else {
        return Err(Error::AccountNotFoundError(username.to_owned()).into());
    };

    let mut passwords: Vec<Password> = vec![];
    for password_result in password_results {
        passwords.push(password_result?);
    }

    Ok(passwords)
}
