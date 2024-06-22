mod common;

use dgruft::backend::*;
use dgruft::helpers;

#[test]
fn file_tests() {}

#[test]
fn password_tests() {
    common::reset_test_db();
    let mut db = database::Database::connect(common::TEST_DB_PATH).unwrap();

    // Create some accounts
    let username_1 = "my_account";
    let password_1 = "this is a passphrase.";

    let username_2 = "pizzaFan123";
    let password_2 = "pleeeease let me in PLEASE PLEASE PLEASE PLEASE PLEASEEEE";

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

    // Add some passwords for these accounts
    let p_1_1_name = "bank";
    let p_1_1_username = "1234 5678 9012 3456";
    let p_1_1_content = "letmein123";
    let p_1_1_notes = "i couldn't think of anything, so i got my password from a list that had a bunch of really common passwords. 

        awesome ὗ";
    let pass_1_1 = password::Password::new(
        &loaded_account_1,
        password_1,
        p_1_1_name,
        p_1_1_username,
        p_1_1_content,
        p_1_1_notes,
    )
    .unwrap();

    let p_2_1_name = "my apartment code";
    let p_2_1_username = "";
    let p_2_1_content = "1234";
    let p_2_1_notes = "don't forget to close the door afterwards!";
    let pass_2_1 = password::Password::new(
        &loaded_account_2,
        password_2,
        p_2_1_name,
        p_2_1_username,
        p_2_1_content,
        p_2_1_notes,
    )
    .unwrap();

    let p_2_2_name = "bank";
    let p_2_2_username = "0987 6543 2109 8765";
    let p_2_2_content = "letmein123";
    let p_2_2_notes = "i got my password from a 'most common passwords' list. yay!";
    let pass_2_2 = password::Password::new(
        &loaded_account_2,
        password_2,
        p_2_2_name,
        p_2_2_username,
        p_2_2_content,
        p_2_2_notes,
    )
    .unwrap();

    assert!(db
        .get_b64_passwords("nonexistentaccount")
        .unwrap()
        .is_none());

    assert!(db
        .get_b64_passwords(username_1)
        .unwrap()
        .unwrap()
        .is_empty());
    assert!(db
        .get_b64_passwords(username_2)
        .unwrap()
        .unwrap()
        .is_empty());

    db.add_new_password(pass_1_1.to_b64()).unwrap();
    db.add_new_password(pass_2_1.to_b64()).unwrap();
    db.add_new_password(pass_2_2.to_b64()).unwrap();

    let dupe_pass_err = db.add_new_password(pass_1_1.to_b64()).unwrap_err();
    if let Some(rusqlite::ErrorCode::ConstraintViolation) = dupe_pass_err.sqlite_error_code() {
    } else {
        panic!("Wrong error type");
    }

    let fields_1 = loaded_account_1.unlock(password_1).unwrap();
    let key_1 = fields_1.key();
    let fields_2 = loaded_account_2.unlock(password_2).unwrap();
    let key_2 = fields_2.key();

    let loaded_passwords_1: Vec<password::Password> = db
        .get_b64_passwords(username_1)
        .unwrap()
        .unwrap()
        .into_iter()
        // .map(|b64password| password::Password::from_b64(b64password).unwrap())
        .map(|b64p_test| {
            dbg!(&b64p_test);
            password::Password::from_b64(b64p_test).unwrap()
        })
        .collect();
    let loaded_passwords_2: Vec<password::Password> = db
        .get_b64_passwords(username_2)
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|b64password| password::Password::from_b64(b64password).unwrap())
        .collect();

    assert_eq!(loaded_passwords_1.len(), 1);
    assert_eq!(loaded_passwords_2.len(), 2);

    fn assert_encrypted_eq(
        unencrypted_str: &str,
        encrypted: &encrypted::Encrypted,
        key: &[u8; 32],
    ) {
        let decrypted_text =
            helpers::bytes_to_utf8(&encrypted.decrypt(key).unwrap(), "decrypted").unwrap();
        dbg!(unencrypted_str, decrypted_text);
        assert_eq!(unencrypted_str.as_bytes(), encrypted.decrypt(key).unwrap());
    }

    fn get_with_name<'a>(
        desired_name: &str,
        key: &[u8; 32],
        passwords: &'a [password::Password],
    ) -> &'a password::Password {
        passwords
            .iter()
            .find(|pwd| {
                helpers::bytes_to_utf8(&pwd.encrypted_name().decrypt(key).unwrap(), desired_name)
                    .unwrap()
                    == desired_name
            })
            .unwrap()
    }

    let loaded_p_1_1 = get_with_name(p_1_1_name, key_1, &loaded_passwords_1);
    let loaded_p_2_1 = get_with_name(p_2_1_name, key_2, &loaded_passwords_2);
    let loaded_p_2_2 = get_with_name(p_2_2_name, key_2, &loaded_passwords_2);

    assert_eq!(username_1, loaded_p_1_1.owner_username());
    assert_encrypted_eq(p_1_1_name, loaded_p_1_1.encrypted_name(), key_1);
    assert_encrypted_eq(p_1_1_username, loaded_p_1_1.encrypted_username(), key_1);
    assert_encrypted_eq(p_1_1_content, loaded_p_1_1.encrypted_content(), key_1);
    assert_encrypted_eq(p_1_1_notes, loaded_p_1_1.encrypted_notes(), key_1);

    assert_eq!(username_2, loaded_p_2_1.owner_username());
    assert_encrypted_eq(p_2_1_name, loaded_p_2_1.encrypted_name(), key_2);
    assert_encrypted_eq(p_2_1_username, loaded_p_2_1.encrypted_username(), key_2);
    assert_encrypted_eq(p_2_1_content, loaded_p_2_1.encrypted_content(), key_2);
    assert_encrypted_eq(p_2_1_notes, loaded_p_2_1.encrypted_notes(), key_2);

    assert_eq!(username_2, loaded_p_2_2.owner_username());
    assert_encrypted_eq(p_2_2_name, loaded_p_2_2.encrypted_name(), key_2);
    assert_encrypted_eq(p_2_2_username, loaded_p_2_2.encrypted_username(), key_2);
    assert_encrypted_eq(p_2_2_content, loaded_p_2_2.encrypted_content(), key_2);
    assert_encrypted_eq(p_2_2_notes, loaded_p_2_2.encrypted_notes(), key_2);
}
