//! Read, write, and store encrypted data.
//!
//! This is a personal project— using `dgruft` for storage of real confidential information is *not
//! recommended*.
#![warn(missing_docs)]

mod backend;
pub mod cli;
#[cfg(feature = "tui")]
mod tui;
pub mod utils;

// Re-exports
pub use cli::arg_parser::Cli;
