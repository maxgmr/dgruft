use clap::Parser;

use crate::utils;

#[derive(Parser, Debug)]
#[command(name = "dgruft")]
#[command(author)]
#[command(version = utils::info())]
#[command(about = "Encrypted storage for passwords & data.")]
pub struct Args {}
