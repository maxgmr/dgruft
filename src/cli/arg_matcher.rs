//! Route arguments to different functions.
use color_eyre::eyre::{self, eyre};

use super::{
    arg_parser::{Cli, Command},
    processes::*,
};

/// This statement matches the CLI arguments with its proper functionality in `processes`.
pub fn match_args(args: Cli) -> eyre::Result<()> {
    // Prompt for password.
    let password = rpassword::prompt_password(format!("Password for {}: ", args.username))?;

    // Match the CLI commands/arguments.
    match args.command {
        Command::Accounts {
            new,
            delete,
            force_delete,
        } => {
            if new {
                new_account(args.username, password)?;
            } else if delete {
                delete_account(args.username, password, false)?;
            } else if force_delete {
                delete_account(args.username, password, true)?;
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
                new_credential(args.username, password, credentialname.unwrap())?;
            } else if open {
                open_credential(args.username, password, credentialname.unwrap())?;
            } else if list {
                list_credentials(args.username, password)?;
            } else if delete {
                delete_credential(args.username, password, credentialname.unwrap(), false)?;
            } else if force_delete {
                delete_credential(args.username, password, credentialname.unwrap(), true)?;
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
                new_file(args.username, password, filename.unwrap())?;
            } else if open {
                open_file(args.username, password, filename.unwrap())?;
            } else if list {
                list_files(args.username, password)?;
            } else if delete {
                delete_file(args.username, password, filename.unwrap(), false)?;
            } else if force_delete {
                delete_file(args.username, password, filename.unwrap(), true)?;
            } else {
                return Err(eyre!("Invalid option combination."));
            }
        }
    }
    Ok(())
}
