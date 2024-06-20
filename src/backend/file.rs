//! Functionality related to reading and writing encrypted files.
use std::{fs::File, path::Path};

use crate::{
    backend::{account::Account, encrypted::Encrypted},
    error::Error,
};

/// Metadata for an encrypted file accessible through `dgruft`.
#[derive(Debug)]
pub struct FileData {
    encrypted_path: Encrypted,
    owner_username: String,
    content_nonce: [u8; 12],
}
impl FileData {
    // /// Create a new [FileData].
    // pub fn new(account: &Account, path: &Path) -> Result<Self, Error> {
    //
    // }
}
