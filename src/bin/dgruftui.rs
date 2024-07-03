//! The TUI version of `dgruft`.
use clap::Parser;
use color_eyre::eyre;

use dgruft::tui::args::Args;

async fn setup() -> eyre::Result<()> {
    // TODO initialise logging
    // TODO initialise panic handler
    let args = Args::parse();

    Ok(())
}

// Tokio main macro allows spawning async Tokio tasks within main.
#[tokio::main]
async fn main() -> eyre::Result<()> {
    if let Err(err) = setup().await {
        eprintln!("dgruft error");
        Err(err)
    } else {
        Ok(())
    }
}
