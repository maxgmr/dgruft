use clap::Parser;
use color_eyre::eyre::{self, eyre};

use dgruft::{
    backend,
    cli::{Cli, Commands},
};

fn match_args(args: Cli) -> eyre::Result<()> {
    match args.command {
        Commands::Account {
            new,
            delete,
            force_delete,
            username,
            password,
        } => {
            if new {
                backend::new_account(username, password)?;
            } else if delete {
                backend::delete_account(username, password, false)?;
            } else if force_delete {
                backend::delete_account(username, password, true)?;
            } else {
                return Err(eyre!(
                    "Impossible option combination: new, delete, force_delete all false."
                ));
            }
        }
        Commands::New {
            username,
            password,
            file,
        } => {
            backend::new_file(username, password, file)?;
        }
        Commands::Edit {
            username,
            password,
            file,
        } => {}
        Commands::List {
            files,
            passwords,
            username,
            password,
        } => {}
    };
    Ok(())
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();
    match_args(args)?;
    Ok(())
}
