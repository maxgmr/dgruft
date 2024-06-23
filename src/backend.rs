//! Backend API.
use std::{
    ffi::OsString,
    fs::{create_dir, remove_dir_all},
    path::PathBuf,
};

use color_eyre::eyre;
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

const VERBOSE: bool = true;
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
    let db = Database::connect(database_path())?;
    if VERBOSE {
        println!("Loaded database @ {:?}.", db.path());
    }
    Ok(db)
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
    if VERBOSE {
        println!(
            "Adding new account with username \"{}\" and password \"{}\"...",
            username, password,
        );
    }

    let mut db = load_db()?;

    // Create Account.
    let account = Account::new(&username, &password)?;

    // Add to database.
    db.add_new_account(account.to_b64())?;

    // Create the directory where this account's files will be stored.
    let acc_dir = acc_path(&username);
    create_dir(&acc_dir)?;
    if VERBOSE {
        println!("Created directory @ {:?}.", acc_dir);
    }
    Ok(())
}

/// Delete an existing account and all its files and passwords.
pub fn delete_account(username: String, password: String, force: bool) -> eyre::Result<()> {
    // TODO
    if VERBOSE {
        println!(
            "Deleting account with username \"{}\" and password \"{}\"...",
            username, password,
        );
    }

    let db = load_db()?;
    // Delete the directory where this account's files were stored
    let acc_dir = acc_path(&username);
    remove_dir_all(&acc_dir)?;

    // Delete this account's database entry
    // TODO

    if VERBOSE {
        println!("Deleted directory @ {:?}.", acc_dir);
    }
    Ok(())
}

/// Create a new file, add its data to the database, and store it in the user directory.
pub fn new_file(username: String, password: String, file: OsString) -> eyre::Result<()> {
    // Load account entry from db.
    let mut db = load_db()?;
    let unlocked_account = login(&mut db, &username, &password)?;

    // Get user directory.
    let mut acc_dir = acc_path(&username);
    acc_dir.push(file);

    // Create new file.
    let file_data =
        FileData::new_with_key(unlocked_account.username(), unlocked_account.key(), acc_dir)?;

    // Add to database— if err then undo file creation.
    // TODO: Create function to insert new file data

    Ok(())
}
