//! Functionality related to saving, loading, and editing files.
use std::{
    fs::{create_dir, metadata, File, OpenOptions},
    io::Read,
};

use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{self, eyre};

use super::super::{
    account::Account,
    encryption::encrypted::{Aes256Key, TryFromEncrypted},
};
use crate::utils::account_dir;

/// Ensure that a given path exists, is a directory, and is not read-only.
pub fn verify_writeable_dir<P>(path: P) -> eyre::Result<()>
where
    P: AsRef<Utf8Path>,
{
    // Check that the path is valid and is a directory.
    let metadata = metadata(path.as_ref())?;
    if !metadata.is_dir() {
        return Err(eyre!("{:?} is not a directory.", path.as_ref()));
    }

    // Ensure that the directory is not read-only.
    let permissions = metadata.permissions();
    if permissions.readonly() {
        return Err(eyre!(
            "Failed to connect to Vault: {:?} is read-only.",
            path.as_ref()
        ));
    }

    Ok(())
}

/// Get an [Account] file directory.
pub fn get_account_file_dir<P>(fs_dir: P, username: &str) -> eyre::Result<Utf8PathBuf>
where
    P: AsRef<Utf8Path>,
{
    let mut dir = Utf8PathBuf::from(fs_dir.as_ref());
    dir.push(username);
    verify_writeable_dir(&dir)?;
    Ok(dir)
}

/// Create an [Account] file directory.
pub fn new_account_file_dir<P>(fs_dir: P, username: &str) -> eyre::Result<()>
where
    P: AsRef<Utf8Path>,
{
    let mut dir = Utf8PathBuf::from(fs_dir.as_ref());
    verify_writeable_dir(&dir)?;
    dir.push(username);
    create_dir(dir)?;
    Ok(())
}

/// Read a [File] as bytes.
pub fn read_file_bytes(mut file: &File) -> eyre::Result<Vec<u8>> {
    let mut bytes: Vec<u8> = vec![];
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Open an existing [File].
pub fn open_file<P>(path: P) -> eyre::Result<File>
where
    P: AsRef<Utf8Path>,
{
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open(path.as_ref())?)
}
