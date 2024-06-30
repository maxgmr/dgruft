//! These are all the functional processes run by `dgruft` CLI commands.
use std::io::{self, Write};

use color_eyre::eyre::{self, eyre};

use crate::{
    backend::{account::Account, vault::Vault},
    utils::{data_dir, db_path},
};

// ACCOUNTS

/// Create a new account.
pub fn new_account(username: String, password: String) -> eyre::Result<()> {
    // Confirm password.
    let confirm_password =
        rpassword::prompt_password(format!("Confirm password for new account {}: ", username))?;
    if confirm_password != password {
        return Err(eyre!("Passwords for new account do not match."));
    }

    // Connect to the vault.
    let mut vault = Vault::connect(db_path()?, data_dir()?)?;

    // Add the new account.
    vault.create_new_account(username, password)?;

    Ok(())
}

/// List all existing accounts.
pub fn list_accounts() -> eyre::Result<()> {
    // Connect to the vault.
    let mut vault = Vault::connect(db_path()?, data_dir()?)?;

    // Load all accounts.
    let accounts = vault.load_all::<Account>()?;

    // Create username list output.
    let username_string = accounts
        .iter()
        .fold(String::new(), |acc, next| acc + next.username() + "\n");

    // Print account usernames.
    println!("{}", username_string);

    Ok(())
}

/// Delete an existing account along with all its files and passwords.
pub fn delete_account(username: String, password: String, force: bool) -> eyre::Result<()> {
    // TODO
    Ok(())
}

// CREDENTIALS

/// Create a new credential.
pub fn new_credential(
    username: String,
    password: String,
    credentialname: String,
) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// Open & edit an existing credential.
pub fn open_credential(
    username: String,
    password: String,
    credentialname: String,
) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// List all credentials owned by the given account.
pub fn list_credentials(username: String, password: String) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// Delete a credential.
pub fn delete_credential(
    username: String,
    password: String,
    credentialname: String,
    force: bool,
) -> eyre::Result<()> {
    // TODO
    Ok(())
}

// FILES

/// Create a new file.
pub fn new_file(username: String, password: String, filename: String) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// Open & edit an existing file.
pub fn open_file(username: String, password: String, filename: String) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// List all files owned by the given account.
pub fn list_files(username: String, password: String) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// Delete a file.
pub fn delete_file(
    username: String,
    password: String,
    filename: String,
    force: bool,
) -> eyre::Result<()> {
    // TODO
    Ok(())
}

// CLI confirmation prompt.
fn cli_confirm(message: String) -> eyre::Result<bool> {
    print!("{}", message);
    let mut input = String::new();
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    match input.to_lowercase().chars().next() {
        Some('y') => Ok(true),
        _ => Ok(false),
    }
}
