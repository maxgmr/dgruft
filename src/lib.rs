//! Modules utilised by dgruft.
//!
//! This is a personal project; using `dgruft` for storage of confidential information is *not
//! recommended*.
#![warn(missing_docs)]

/// Backend code for dgruft.
pub mod backend;
#[cfg(feature = "frontend")]
/// Frontend code for dgruft.
pub mod frontend;
