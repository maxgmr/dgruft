//! Read, write, and store encrypted data.
//!
//! This is a personal project— using `dgruft` for storage of real confidential information is *not
//! recommended*.
#![warn(missing_docs)]
#![allow(dead_code)]

mod backend;
mod cli;
#[cfg(feature = "tui")]
mod tui;
mod utils;
