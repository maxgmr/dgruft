//! Backend API.
use std::{
    fs::{create_dir, remove_dir_all},
    path::PathBuf,
};

use color_eyre::eyre;

pub mod account;
pub mod database;
pub mod encrypted;
pub mod file;
pub mod hashed;
pub mod password;
mod sql_schemas;
mod sql_statements;

use crate::helpers;
use account::Account;
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
    if VERBOSE {
        println!("Deleted directory @ {:?}.", acc_dir);
    }
    Ok(())
}
