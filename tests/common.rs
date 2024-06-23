// Common functionality for integration tests
use std::{path::PathBuf, process::Command};

pub const TEST_DB_PATH: &str = "dbs/dgruft-test.db";

pub fn get_test_dir() -> PathBuf {
    PathBuf::from("test_files")
}

pub fn reset_test_db() {
    Command::new("rm")
        .arg(TEST_DB_PATH)
        .status()
        .expect("failed");
    Command::new("touch")
        .arg(TEST_DB_PATH)
        .status()
        .expect("failed");
}

