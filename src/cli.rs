//! Functionality related to the command line.
use std::ffi::OsString;

use clap::{ArgGroup, Parser, Subcommand};

use crate::helpers;

/// The command-line interface.
#[derive(Parser, Debug)]
#[command(author, version = helpers::version(), about = "Encrypted storage for passwords and data.")]
pub struct Cli {
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
            .requires("username")
            .requires("password"),
))]
    Account {
        /// Add the chosen account.
        #[clap(short, long)]
        new: bool,
        /// Delete the chosen account.
        #[clap(short = 'd', long = "delete")]
        delete: bool,
        /// Delete the chosen account without confirmation.
        #[clap(short = 'D', long = "deleteforce")]
        force_delete: bool,
        /// Your account's username.
        username: String,
        /// Your account's password.
        password: String,
    },

    /// Create a new file.
    #[command(arg_required_else_help = true)]
    New {
        /// Your account's username.
        username: String,
        /// Your account's password.
        password: String,
        /// The name of your new file.
        filename: OsString,
    },

    /// Edit an existing file.
    #[command(arg_required_else_help = true)]
    Edit {
        /// Your account's username.
        username: String,
        /// Your account's password.
        password: String,
        /// The name of the file you wish to edit.
        filename: OsString,
    },

    /// List the names of your account's files or passwords.
    #[command(arg_required_else_help = true)]
    #[clap(group(
            ArgGroup::new("list")
                .required(true)
                .args(&["files", "passwords"])
                .requires("username")
                .requires("password")
))]
    List {
        /// List this account's file names.
       #[clap(short, long)] 
        files: bool,
        /// List this account's password names.
        #[clap(short, long)]
        passwords: bool,
        /// Your account's username.
        username: String,
        /// Your account's password.
        password: String,
    }
}
