//! These are all the functional processes run by `dgruft` CLI commands.
use std::io::{self, Write};

use color_eyre::eyre::{self, eyre};

use crate::{
    backend::{Account, Credential, FileData, UnlockedAccount, Vault},
    utils::{data_dir, db_path},
};

// ACCOUNTS

/// Create a new account.
pub fn new_account(username: String) -> eyre::Result<()> {
    // Prompt for password.
    let password = prompt_password(&username)?;
    // Confirm password.
    let confirm_password =
        rpassword::prompt_password(format!("Confirm password for new account {}: ", username))?;
    if confirm_password != password {
        return Err(eyre!("Passwords for new account do not match."));
    }

    // Connect to the vault.
    let mut vault = vault_connect()?;

    // Add the new account.
    vault.create_new_account(username, password)?;

    Ok(())
}

/// List all existing accounts.
pub fn list_accounts() -> eyre::Result<()> {
    // Connect to the vault.
    let vault = vault_connect()?;

    // Load all accounts.
    let mut accounts = vault.load_all::<Account>()?;
    accounts.sort_unstable();

    // Create username list output.
    let username_string = accounts
        .iter()
        .fold(String::new(), |acc, next| acc + next.username() + "\n");

    // Print account usernames.
    println!("{}", username_string);

    Ok(())
}

/// Change an account's password.
pub fn change_password(username: String) -> eyre::Result<()> {
    // Connect to the vault.
    let mut vault = vault_connect()?;
    // Login.
    let unlocked = login(&vault, &username)?;

    // Confirm new password.
    let new_password =
        rpassword::prompt_password(format!("New password for account {}: ", username))?;
    let confirm_new_password =
        rpassword::prompt_password(format!("Confirm new password for account {}: ", username))?;
    if confirm_new_password != new_password {
        return Err(eyre!("New passwords do not match."));
    }

    // Update account password.
    vault.change_account_password(username, unlocked.password(), new_password)
}

/// Delete an existing account along with all its files and passwords.
pub fn delete_account(username: String, force: bool) -> eyre::Result<()> {
    // Connect to the vault.
    let mut vault = vault_connect()?;
    // Login.
    let unlocked = login(&vault, &username)?;

    // Get all files & credentials of this account.
    let credentials = vault.load_account_credentials(&username)?;
    let files = vault.load_account_files_data(&username)?;

    if !force
        && !cli_confirm(
            format!(
                "Really delete account {} with {} credential(s) & {} file(s)? [y/N] ",
                unlocked.username(),
                credentials.len(),
                files.len()
            ),
            false,
        )?
    {
        println!("Account deletion cancelled.");
        return Ok(());
    }

    // Delete account and all its associated files.
    vault.delete_account(username)?;

    Ok(())
}

// CREDENTIALS

/// Create a new credential.
pub fn new_credential(username: String, credentialname: String) -> eyre::Result<()> {
    // Connect to the vault.
    let mut vault = vault_connect()?;
    // Login.
    let unlocked = login(&vault, &username)?;

    // Prompt for credential name.
    let credential_username = cli_prompt(format!("{} username: ", credentialname))?;
    let credential_password = cli_prompt(format!("{} password: ", credentialname))?;
    let credential_notes = cli_prompt(format!("{} notes: ", credentialname))?;

    // Add credential to vault.
    vault.create_credential(
        unlocked.username(),
        unlocked.key(),
        credentialname,
        credential_username,
        credential_password,
        credential_notes,
    )?;

    Ok(())
}

/// Open & edit an existing credential.
pub fn open_credential(username: String, credentialname: String) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// List all credentials owned by the given account.
pub fn list_credentials(username: String) -> eyre::Result<()> {
    // Connect to the vault.
    let vault = vault_connect()?;
    // Login.
    let unlocked = login(&vault, &username)?;

    // Load all credentials.
    let credentials = vault.load_all::<Credential>()?;
    // Convert to credential names.
    let mut credential_names = credentials
        .iter()
        .map(|cred| cred.name::<String>(unlocked.key()).unwrap_or_default())
        .collect::<Vec<String>>();

    credential_names.sort_unstable();

    let credential_names_string = credential_names
        .iter()
        .fold(String::new(), |acc, next| acc + &next + "\n");

    // Print credential names.
    println!("{}", credential_names_string);

    Ok(())
}

/// Delete a credential.
pub fn delete_credential(
    username: String,
    credentialname: String,
    force: bool,
) -> eyre::Result<()> {
    // TODO
    Ok(())
}

// FILES

/// Create a new file.
pub fn new_file(username: String, filename: String) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// Open & edit an existing file.
pub fn open_file(username: String, filename: String) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// List all files owned by the given account.
pub fn list_files(username: String) -> eyre::Result<()> {
    // TODO
    Ok(())
}

/// Delete a file.
pub fn delete_file(username: String, filename: String, force: bool) -> eyre::Result<()> {
    // TODO
    Ok(())
}

// HELPERS

// Connect to the vault.
fn vault_connect() -> eyre::Result<Vault> {
    Vault::connect(db_path()?, data_dir()?)
}

// Verify login into correct, returning account data.
fn login(vault: &Vault, username: &str) -> eyre::Result<UnlockedAccount> {
    let password = prompt_password(username)?;
    vault.load_unlocked_account(username, &password)
}

// Password prompt.
fn prompt_password(username: &str) -> eyre::Result<String> {
    Ok(rpassword::prompt_password(format!(
        "Password for {}: ",
        username
    ))?)
}

// General CLI prompt.
fn cli_prompt(message: String) -> eyre::Result<String> {
    print!("{}", message);
    let mut input = String::new();
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    Ok(input)
}

// CLI confirmation message.
fn cli_confirm(message: String, default: bool) -> eyre::Result<bool> {
    let input = cli_prompt(message)?;
    if default {
        match input.to_lowercase().chars().next() {
            Some('n') => Ok(true),
            _ => Ok(false),
        }
    } else {
        match input.to_lowercase().chars().next() {
            Some('y') => Ok(true),
            _ => Ok(false),
        }
    }
}
