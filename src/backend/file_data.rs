//! Functionality for data associated with user files stored in the `dgruft` filesystem.
use camino::{Utf8Path, Utf8PathBuf};

use super::encryption::encrypted::Aes256Nonce;

#[derive(Debug, PartialEq, Eq)]
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

    /// Create a [FileData] from its fields.
    pub fn from_fields(
        path: Utf8PathBuf,
        filename: String,
        owner_username: String,
        contents_nonce: Aes256Nonce,
    ) -> Self {
        Self {
            path,
            filename,
            owner_username,
            contents_nonce,
        }
    }

    /// Return the `path` of this [FileData].
    pub fn path(&self) -> &Utf8Path {
        &self.path
    }

    /// Return the `filename` of this [FileData].
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Return the `owner_username` of this [FileData].
    pub fn owner_username(&self) -> &str {
        &self.owner_username
    }

    /// Return the `contents_nonce` of this [FileData].
    pub fn contents_nonce(&self) -> Aes256Nonce {
        self.contents_nonce
    }
}
