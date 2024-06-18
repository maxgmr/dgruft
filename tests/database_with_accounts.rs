mod common;

use dgruft::backend::*;

#[test]
fn test_database_with_accounts() {
    let username_1 = "my_account";
    let password_1 = "this is a passphrase.";

    let username_2 = "pizzaFan123";
    let password_2 = "pleeeease let me in PLEASE PLEASE PLEASE PLEASE PLEASEEEE";

    common::reset_test_db();
    let mut db = database::Database::connect(common::TEST_DB_PATH).unwrap();

    let account_1 = account::Account::new(username_1, password_1).unwrap();
    let account_2 = account::Account::new(username_2, password_2).unwrap();

    db.add_new_account(account_1.to_b64()).unwrap();
    db.add_new_account(account_2.to_b64()).unwrap();

    let account_2_dupe = account::Account::new(username_2, "iLoveBaseball123").unwrap();
    let dupe_acc_err = db.add_new_account(account_2_dupe.to_b64()).unwrap_err();
    if let Some(rusqlite::ErrorCode::ConstraintViolation) = dupe_acc_err.sqlite_error_code() {
    } else {
        panic!("Wrong error type");
    }

    let loaded_account_1 =
        account::Account::from_b64(db.get_b64_account(username_1).unwrap().unwrap()).unwrap();
    let loaded_account_2 =
        account::Account::from_b64(db.get_b64_account(username_2).unwrap().unwrap()).unwrap();
    assert_eq!(loaded_account_1.username(), username_1);
    assert_eq!(loaded_account_2.username(), username_2);
    assert_eq!(loaded_account_1.username(), account_1.username());
    assert_eq!(loaded_account_2.username(), account_2.username());
    assert!(loaded_account_1.check_password_match(password_1));
    assert!(loaded_account_2.check_password_match(password_2));
    assert!(!loaded_account_2.check_password_match(password_1));
    assert!(!loaded_account_1.check_password_match(password_2));

    if db.get_b64_account("bleurgh").unwrap().is_none() {
    } else {
        panic!("Should have returned None");
    };
}
