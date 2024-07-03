//! CLI argument parsing for the TUI version of `dgruft`.
use clap::Parser;

use crate::utils;

/// The parser for CLI arguments in the TUI version of `dgruft`.
#[derive(Parser, Debug)]
#[command(name = "dgruft")]
#[command(author)]
#[command(version = utils::info())]
#[command(about = "Encrypted storage for passwords & data.")]
pub struct Args {}
