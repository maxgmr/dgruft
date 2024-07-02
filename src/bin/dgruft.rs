//! Launcher for CLI mode.
use clap::Parser;
use color_eyre::eyre;

use dgruft::{cli::arg_matcher, utils, Cli};

fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    // Setup: If certain paths don't exist, create them.
    utils::setup()?;

    let args = Cli::parse();
    arg_matcher::match_args(args)?;
    Ok(())
}
