//! Utilities for editing files.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{self};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use uuid::Uuid;

// Number of times file gets overwritten when being shredded.
const PASSES: usize = 3;

/// Edit something in the default editor, returning a string.
pub fn edit_string<P, B>(temp_directory: P, input: B) -> eyre::Result<String>
where
    P: AsRef<Utf8Path>,
    B: AsRef<[u8]>,
{
    Ok(String::from_utf8(edit_bytes(temp_directory, input)?)?)
}

// /// Open something in the default editor, returning bytes.
pub fn edit_bytes<P, B>(temp_directory: P, input: B) -> eyre::Result<Vec<u8>>
where
    P: AsRef<Utf8Path>,
    B: AsRef<[u8]>,
{
    // Create tempfile & write input to it.
    let tempfile_path = new_tempfile(temp_directory)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open(&tempfile_path)?;
    file.write_all(input.as_ref())?;

    // Edit that file.
    edit::edit_file(&tempfile_path)?;

    // Read the contents of the file.
    file.seek(SeekFrom::Start(0))?;
    let mut buf: Vec<u8> = vec![];
    file.read_to_end(&mut buf)?;

    // Delete that file.
    shred_tempfile(tempfile_path)?;

    // Return the edited contents.
    Ok(buf)
}

// Create a new tempfile and return the path to it.
fn new_tempfile<P: AsRef<Utf8Path>>(temp_directory: P) -> eyre::Result<Utf8PathBuf> {
    let mut temp_dir: Utf8PathBuf = temp_directory.as_ref().to_path_buf();
    let tempfile_name = format!("{}.tmp", Uuid::new_v4());
    temp_dir.push(tempfile_name);
    File::create(&temp_dir)?;
    Ok(temp_dir)
}

// Overwrite the tempfile with random bytes, then delete it.
fn shred_tempfile<P: AsRef<Utf8Path>>(path: P) -> eyre::Result<()> {
    let mut tempfile = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open(path.as_ref())?;
    let tempfile_len = tempfile.metadata()?.len();

    for _ in 0..PASSES {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut rand_bytes_vec = vec![0u8; tempfile_len.try_into().unwrap()];
        rng.fill_bytes(&mut rand_bytes_vec);
        tempfile.write_all(&rand_bytes_vec)?;
    }

    fs::remove_file(path.as_ref())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TEMP_DIR: &str = "tests/temp";

    fn refresh_temp_dir(dirname: &str) -> eyre::Result<Utf8PathBuf> {
        let mut dir = Utf8PathBuf::from(TEST_TEMP_DIR);
        dir.push(dirname);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[test]
    fn tempfile_create_shred() {
        let dirname = "create_shred";
        let dirpath = refresh_temp_dir(dirname).unwrap();

        let tempfile = new_tempfile(dirpath).unwrap();
        tempfile.metadata().unwrap();

        shred_tempfile(&tempfile).unwrap();
        tempfile.metadata().unwrap_err();
    }

    // Must be manually tested; run with `cargo t -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn string_edit() {
        let dirname = "string_edit";
        let dirpath = refresh_temp_dir(dirname).unwrap();

        let starting_test = "My Christmas Shopping List... TOP SECRET!

Charlie: Football
Pam: Dollhouse
My Karate Instructor Dave: 剑, 双节棍

DON'T TELL ANYONE!!!!";

        let edited = edit_string(dirpath, starting_test).unwrap();
        println!("{}", edited);
    }
}
