//! Read, write, and store encrypted data.
//!
//! This is a personal project— using `dgruft` for storage of real confidential information is *not
//! recommended*.
#![warn(missing_docs)]

mod backend;
mod cli;
#[cfg(feature = "frontend")]
mod tui;
mod utils;
