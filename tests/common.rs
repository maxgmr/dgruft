// Common functionality for integration tests
use dgruft::backend::*;

pub const TEST_DB_PATH: &str = "dbs/dgruft-test.db";

pub fn reset_test_db() {
    let mut db = database::Database::connect(TEST_DB_PATH).unwrap();
    db.truncate_table("user_credentials").unwrap();
    db.truncate_table("passwords").unwrap();
    db.truncate_table("files").unwrap();
}
