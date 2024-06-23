use clap::Parser;
use color_eyre::eyre;

use dgruft::cli::Cli;

fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();
    Ok(())
}
