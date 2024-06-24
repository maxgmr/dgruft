//! Modules utilised by `dgruft`.
//!
//! This is a personal project; using `dgruft` for storage of confidential information is *not
//! recommended*.
#![warn(missing_docs)]

/// Backend code for `dgruft`.
pub mod backend;
/// Command line argument parsing.
pub mod cli;
/// `dgruft`-specific errors.
pub mod error;
#[cfg(feature = "frontend")]
/// Frontend code for `dgruft`.
pub mod frontend;
/// Small, general helper functions.
pub mod helpers;
