//! Functionality related to the command line.
use clap::Parser;

use crate::helpers;

#[derive(Parser, Debug)]
#[command(author, version = helpers::version(), about = "Encrypted storage for passwords and data.")]
pub struct Cli {
    /// Account username
    #[arg(short, long)]
    username: String,
}
