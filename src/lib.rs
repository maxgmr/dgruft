//! Storage, editing, reading, and writing of encrypted files and credentials.
#![warn(missing_docs)]

/// Backend functionality.
mod backend;
/// CLI interface.
mod cli;
#[cfg(feature = "frontend")]
/// GUI interface.
mod frontend;
/// General program utilities.
mod utils;
