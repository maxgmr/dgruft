// Common functionality for integration tests
use std::process::Command;

pub const TEST_DB_PATH: &str = "dbs/dgruft-test.db";

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