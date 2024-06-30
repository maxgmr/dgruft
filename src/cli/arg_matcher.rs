//! Route arguments to different functions.
use color_eyre::eyre::{self, eyre};

use super::{
    arg_parser::{Cli, Command},
    processes::*,
};

/// This statement matches the CLI arguments with its proper functionality in `processes`.
pub fn match_args(args: Cli) -> eyre::Result<()> {
    // Match the CLI commands/arguments.
    match args.command {
        Command::Accounts {
            new,
            list,
            password_change,
            delete,
            force_delete,
        } => {
            if new {
                new_account(args.username)?;
            } else if list {
                list_accounts()?;
            } else if password_change {
                change_password(args.username)?;
            } else if delete {
                delete_account(args.username, false)?;
            } else if force_delete {
                delete_account(args.username, true)?;
            } else {
                return Err(eyre!("Invalid option combination."));
            }
        }
        Command::Credentials {
            new,
            open,
            list,
            delete,
            force_delete,
            credentialname,
        } => {
            if new {
                new_credential(args.username, credentialname.unwrap())?;
            } else if open {
                open_credential(args.username, credentialname.unwrap())?;
            } else if list {
                list_credentials(args.username)?;
            } else if delete {
                delete_credential(args.username, credentialname.unwrap(), false)?;
            } else if force_delete {
                delete_credential(args.username, credentialname.unwrap(), true)?;
            } else {
                return Err(eyre!("Invalid option combination."));
            }
        }
        Command::Files {
            new,
            open,
            list,
            delete,
            force_delete,
            filename,
        } => {
            if new {
                new_file(args.username, filename.unwrap())?;
            } else if open {
                open_file(args.username, filename.unwrap())?;
            } else if list {
                list_files(args.username)?;
            } else if delete {
                delete_file(args.username, filename.unwrap(), false)?;
            } else if force_delete {
                delete_file(args.username, filename.unwrap(), true)?;
            } else {
                return Err(eyre!("Invalid option combination."));
            }
        }
    }
    Ok(())
}
