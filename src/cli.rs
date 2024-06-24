//! Functionality related to the command line.
use std::ffi::OsString;

use clap::{ArgGroup, Parser, Subcommand};

use crate::helpers;

/// The command-line interface.
#[derive(Parser, Debug)]
#[command(author, version = helpers::version(), about = "Encrypted storage for passwords and data.")]
pub struct Cli {
    /// Account username.
    pub username: String,
    /// All the possible commands the user can give CLI `dgruft`.
    #[command(subcommand)]
    pub command: Commands,
}

/// All the possible commands the user can give CLI `dgruft`.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Manage accounts.
    #[command(arg_required_else_help = true)]
    #[clap(group(
            ArgGroup::new("account")
                .required(true)           
                .args(&["new", "delete", "force_delete"])
    ))]
    Account {
        /// Add the account.
        #[clap(short, long)]
        new: bool,
        /// Delete the account.
        #[clap(short = 'd', long = "delete")]
        delete: bool,
        /// Delete the account without confirmation.
        #[clap(short = 'D', long = "deleteforce")]
        force_delete: bool,
    },

    /// Manage files.
    #[command(arg_required_else_help = true)]
    #[command(alias = "file")]
    #[command(alias = "f")]
    #[clap(group(
            ArgGroup::new("file")
                .required(true)           
                .args(&["new", "open", "list", "delete", "force_delete"])
    ))]
    Files {
        /// Create the file.
        #[clap(short, long, requires="filename")]
        new: bool,
        /// Open the file.
        #[clap(short, long, requires="filename")]
        open: bool,
        /// List all files owned by this account.
        #[clap(short, long)]
        list: bool,
        /// Delete the file.
        #[clap(short = 'd', long = "delete", requires="filename")]
        delete: bool,
        /// Delete the file without confirmation.
        #[clap(short = 'D', long = "forcedelete", requires="filename")]
        force_delete: bool,
        /// The name of the file.
        filename: Option<OsString>,
    },

    /// Manage passwords.
    #[command(arg_required_else_help = true)]
    #[command(alias = "password")]
    #[command(alias = "p")]
    #[clap(group(
            ArgGroup::new("password")
                .required(true)           
                .args(&["new", "open", "list", "delete", "force_delete"])
    ))]
    Passwords {
        /// Create the password.
        #[clap(short, long, requires="passwordname")]
        new: bool,
        /// Open the password.
        #[clap(short, long, requires="passwordname")]
        open: bool,
        /// List all passwords owned by this account.
        #[clap(short, long)]
        list: bool,
        /// Delete the password.
        #[clap(short = 'd', long = "delete", requires="passwordname")]
        delete: bool,
        /// Delete the password without confirmation.
        #[clap(short = 'D', long = "forcedelete", requires="passwordname")]
        force_delete: bool,
        /// The name of the password.
        passwordname: Option<OsString>,
    },
}
