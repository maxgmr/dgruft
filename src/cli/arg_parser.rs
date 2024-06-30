//! Parse command-line arguments for the CLI version of `dgruft`.
use clap::{ArgGroup, Parser, Subcommand};
use color_eyre::eyre::{self, eyre};

use crate::utils;

/// The command-line interface argument parser.
#[derive(Parser, Debug)]
#[command(name = "dgruft")]
#[command(author)]
#[command(version = utils::info())]
#[command(about = "Encrypted storage for passwords & data.")]
pub struct Cli {
    /// Account username.
    pub username: String,
    /// All the possible commands the user can give CLI `dgruft`.
    #[command(subcommand)]
    pub command: Command,
}

/// All the possible commands the user can give CLI `dgruft`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Account-related functionality.
    #[command(arg_required_else_help = true)]
    #[clap(alias = "account")]
    #[clap(alias = "a")]
    #[clap(
        group(
            ArgGroup::new("account")
                .required(true)
                .args(&["new", "delete", "force_delete"])
        )
    )]
    Accounts {
        /// Create a new account.
        #[clap(short, long)]
        new: bool,
        /// Delete an account.
        #[clap(short = 'd', long = "delete")]
        delete: bool,
        /// Delete an account without confirmation.
        #[clap(short = 'D', long = "forcedelete")]
        force_delete: bool,
    },

    /// File-related functionality.
    #[command(arg_required_else_help = true)]
    #[command(alias = "file")]
    #[command(alias = "f")]
    #[clap(
        group(
            ArgGroup::new("file")
                .required(true)
                .args(&["new", "open", "list", "delete", "force_delete"])
        )
    )]
    Files {
        /// Create a new file.
        #[clap(short, long, requires = "filename")]
        new: bool,
        /// Open & edit a file.
        #[clap(short, long, requires = "filename")]
        open: bool,
        /// List all files owned by this account.
        #[clap(short, long)]
        list: bool,
        /// Delete a file.
        #[clap(short = 'd', long = "delete", requires = "filename")]
        delete: bool,
        /// Delete a file without confirmation.
        #[clap(short = 'd', long = "delete", requires = "filename")]
        force_delete: bool,
        /// The name of the file.
        filename: Option<String>,
    },
    /// Credential-related functionality.
    #[command(arg_required_else_help = true)]
    #[command(alias = "credential")]
    #[command(alias = "c")]
    #[command(alias = "password")]
    #[command(alias = "passwords")]
    #[command(alias = "p")]
    #[clap(
        group(
            ArgGroup::new("credential")
                .required(true)
                .args(&["new", "open", "list", "delete", "force_delete"])
        )
    )]
    Credentials {
        /// Create a new credential.
        #[clap(short, long, requires = "credentialname")]
        new: bool,
        /// Open & edit a credential.
        #[clap(short, long, requires = "credentialname")]
        open: bool,
        /// List all credentials owned by this account.
        #[clap(short, long)]
        list: bool,
        /// Delete a credential.
        #[clap(short = 'd', long = "delete", requires = "credentialname")]
        delete: bool,
        /// Delete a credential without confirmation.
        #[clap(short = 'D', long = "forcedelete", requires = "credentialname")]
        force_delete: bool,
        /// The name of the credential.
        credentialname: Option<String>,
    },
}
