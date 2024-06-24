use clap::Parser;
use color_eyre::eyre::{self, eyre};

use dgruft::{
    backend,
    cli::{Cli, Commands},
};

fn match_args(args: Cli) -> eyre::Result<()> {
    let password = rpassword::prompt_password(format!("Password for {}: ", args.username))?;
    match args.command {
        Commands::Account {
            new,
            delete,
            force_delete,
        } => {
            if new {
                backend::new_account(args.username, password)?;
            } else if delete {
                backend::delete_account(args.username, password, false)?;
            } else if force_delete {
                backend::delete_account(args.username, password, true)?;
            } else {
                return Err(eyre!(
                    "Impossible option combination: new, delete, force_delete all false."
                ));
            }
        }
        Commands::Files {
            new,
            open,
            list,
            delete,
            force_delete,
            filename,
        } => {
            if new {
                backend::new_file(args.username, password, filename.unwrap())?;
            } else if open {
                backend::open_file(args.username, password, filename.unwrap())?;
            } else if list {
                backend::list_files(args.username, password)?;
            } else if delete {
                backend::delete_file(args.username, password, filename.unwrap(), false)?;
            } else if force_delete {
                backend::delete_file(args.username, password, filename.unwrap(), true)?;
            } else {
                return Err(eyre!(
                    "Impossible option combination: new, open, list, delete, force_delete all false."
                ));
            }
        }
        Commands::Passwords {
            new,
            open,
            list,
            delete,
            force_delete,
            passwordname,
        } => {
            if new {
                backend::new_password(args.username, password, passwordname.unwrap())?;
            } else if open {
                backend::open_password(args.username, password, passwordname.unwrap())?;
            } else if list {
                backend::list_passwords(args.username, password)?;
            } else if delete {
                backend::delete_password(args.username, password, passwordname.unwrap(), false)?;
            } else if force_delete {
                backend::delete_password(args.username, password, passwordname.unwrap(), true)?;
            } else {
                return Err(eyre!(
                    "Impossible option combination: new, open, list, delete, force_delete all false."
                ));
            }
        }
    };
    Ok(())
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();
    match_args(args)?;
    Ok(())
}
