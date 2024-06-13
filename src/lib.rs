//! Modules utilised by dgruft.
#![warn(missing_docs)]

/// Backend code for dgruft.
pub mod backend;
#[cfg(feature = "frontend")]
/// Frontend code for dgruft.
pub mod frontend;
