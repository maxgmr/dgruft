//! These are all the functional processes run by `dgruft` CLI commands.
use std::io::{self, Write};

use color_eyre::eyre::{self, eyre};

use crate::{
    backend::{Account, CredentialUpdateField, FileData, UnlockedAccount, Vault},
    edit::{edit_bytes, edit_string},
    utils::{data_dir, db_path, temp_dir},
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
    vault.create_new_account(&username, password)?;

    println!("Account {} created.", username);
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
    vault.change_account_password(&username, unlocked.password(), new_password)?;

    println!("{} password updated.", username);
    Ok(())
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
    vault.delete_account(&username)?;

    println!("Account {} deleted.", username);
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
        &credentialname,
        credential_username,
        credential_password,
        credential_notes,
    )?;

    println!("Credential \"{}\" created.", credentialname);
    Ok(())
}

/// Edit an existing credential.
pub fn edit_credential(username: String, credentialname: String) -> eyre::Result<()> {
    // Connect to the vault.
    let mut vault = vault_connect()?;
    // Login.
    let unlocked = login(&vault, &username)?;
    let key = unlocked.key();

    // Load the credential & its fields.
    let credential = vault.load_credential(&username, &credentialname, key)?;
    let mut credential_username: String = credential.username(key)?;
    let mut credential_password: String = credential.password(key)?;
    let mut credential_notes: String = credential.notes(key)?;

    // Prompt to edit each credential field.
    if cli_confirm(
        format!(
            "Username: \"{}\"\nEdit username? [Y/n] ",
            credential_username
        ),
        true,
    )? {
        credential_username = edit_string(temp_dir()?, credential_username)?;
    }
    vault.update_credential(
        &username,
        &credentialname,
        key,
        CredentialUpdateField::UsernameCipherbytes,
        CredentialUpdateField::UsernameNonce,
        &credential_username,
    )?;

    if cli_confirm(
        format!(
            "Password: \"{}\"\nEdit password? [Y/n] ",
            credential_password
        ),
        true,
    )? {
        credential_password = edit_string(temp_dir()?, credential_password)?;
    }
    vault.update_credential(
        &username,
        &credentialname,
        key,
        CredentialUpdateField::PasswordCipherbytes,
        CredentialUpdateField::PasswordNonce,
        &credential_password,
    )?;

    if cli_confirm(
        format!("Notes: \"{}\"\nEdit notes? [Y/n] ", credential_notes),
        true,
    )? {
        credential_notes = edit_string(temp_dir()?, credential_notes)?;
    }
    vault.update_credential(
        &username,
        &credentialname,
        key,
        CredentialUpdateField::NotesCipherbytes,
        CredentialUpdateField::NotesNonce,
        &credential_notes,
    )?;

    println!("Credential \"{}\" edited successfully.", credentialname);
    Ok(())
}

/// View an existing credential.
pub fn view_credential(username: String, credentialname: String) -> eyre::Result<()> {
    // Connect to the vault.
    let vault = vault_connect()?;
    // Login.
    let unlocked = login(&vault, &username)?;
    let key = unlocked.key();

    // Load the credential & its fields.
    let credential = vault.load_credential(&username, &credentialname, key)?;
    let credential_username: String = credential.username(key)?;
    let credential_password: String = credential.password(key)?;
    let credential_notes: String = credential.notes(key)?;

    // Output credential
    println!(
        "Credential \"{}\"\nUsername: {}Password: {}Notes:{}",
        credentialname, credential_username, credential_password, credential_notes
    );

    Ok(())
}

/// List all credentials owned by the given account.
pub fn list_credentials(username: String) -> eyre::Result<()> {
    // Connect to the vault.
    let vault = vault_connect()?;
    // Login.
    let unlocked = login(&vault, &username)?;

    // Load all owned credentials.
    let credentials = vault.load_account_credentials(&username)?;
    // Convert to credential names.
    let mut credential_names = credentials
        .iter()
        .map(|cred| cred.name::<String>(unlocked.key()).unwrap_or_default())
        .collect::<Vec<String>>();

    credential_names.sort_unstable();

    let credential_names_string = credential_names
        .iter()
        .fold(String::new(), |acc, next| acc + next + "\n");

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
    // Connect to the vault.
    let mut vault = vault_connect()?;
    // Login.
    let unlocked = login(&vault, &username)?;

    // Load credential.
    let credential = vault.load_credential(unlocked.username(), credentialname, unlocked.key())?;
    let loaded_name: String = credential.name(unlocked.key())?;

    if !force
        && !cli_confirm(
            format!("Really delete credential \"{}\"? [y/N] ", loaded_name,),
            false,
        )?
    {
        println!("Credential deletion cancelled.");
        return Ok(());
    }

    // Delete credential.
    vault.delete_credential(username, &loaded_name, unlocked.key())?;

    println!("Credential \"{}\" deleted.", loaded_name);
    Ok(())
}

// FILES

/// Create a new file.
pub fn new_file(username: String, filename: String) -> eyre::Result<()> {
    // Connect to the vault.
    let mut vault = vault_connect()?;
    // Login.
    let unlocked = login(&vault, &username)?;

    // Add empty file to vault.
    vault.create_file(&filename, username, &b""[..], unlocked.key())?;

    println!("File \"{}\" created.", filename);
    Ok(())
}

/// Open & edit an existing file.
pub fn open_file(username: String, filename: String) -> eyre::Result<()> {
    // Connect to the vault.
    let mut vault = vault_connect()?;
    // Login.
    let unlocked = login(&vault, &username)?;

    // Load file.
    let (_, file_contents): (_, Vec<u8>) = vault.load_file(&username, &filename, unlocked.key())?;

    // Edit file.
    let edited_file_contents = edit_bytes(temp_dir()?, file_contents)?;

    // Update file.
    vault.update_file(&username, &filename, unlocked.key(), edited_file_contents)?;

    println!("File \"{}\" updated successfully.", filename);
    Ok(())
}

/// List all files owned by the given account.
pub fn list_files(username: String) -> eyre::Result<()> {
    // Connect to the vault.
    let vault = vault_connect()?;
    // Login.
    login(&vault, &username)?;

    // Load all owned files data.
    let files = vault.load_account_files_data(&username)?;
    // Convert to file names.
    let mut file_names = files
        .iter()
        .map(|file| file.filename())
        .collect::<Vec<&str>>();

    file_names.sort_unstable();

    let file_names_string = file_names
        .iter()
        .fold(String::new(), |acc, next| acc + next + "\n");

    // Print file names.
    println!("{}", file_names_string);

    Ok(())
}

/// Delete a file.
pub fn delete_file(username: String, filename: String, force: bool) -> eyre::Result<()> {
    // Connect to the vault.
    let mut vault = vault_connect()?;
    // Login.
    let unlocked = login(&vault, &username)?;

    // Load file data.
    let (file_data, file_contents): (FileData, Vec<u8>) =
        vault.load_file(unlocked.username(), filename, unlocked.key())?;

    if !force
        && !cli_confirm(
            format!(
                "Really delete file \"{}\" ({} bytes)? [y/N] ",
                file_data.filename(),
                file_contents.len()
            ),
            false,
        )?
    {
        println!("File deletion cancelled.");
        return Ok(());
    }

    // Delete file.
    vault.delete_file(username, file_data.filename())?;

    println!("File \"{}\" deleted.", file_data.filename());
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
            Some('n') => Ok(false),
            _ => Ok(true),
        }
    } else {
        match input.to_lowercase().chars().next() {
            Some('y') => Ok(true),
            _ => Ok(false),
        }
    }
}
