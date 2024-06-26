//! Functionality for data associated with user files stored in the `dgruft` filesystem.
use camino::{Utf8Path, Utf8PathBuf};

use super::encryption::encrypted::Aes256Nonce;

#[derive(Debug)]
pub struct FileData {
    path: Utf8PathBuf,
    filename: String,
    owner_username: String,
    contents_nonce: Aes256Nonce,
}
impl FileData {
    /// Create a new, empty [FileData].
    pub fn new<P>(
        path: P,
        filename: String,
        owner_username: String,
        contents_nonce: Aes256Nonce,
    ) -> Self
    where
        P: AsRef<Utf8Path>,
    {
        Self {
            path: path.as_ref().into(),
            filename,
            owner_username,
            contents_nonce,
        }
    }
}
