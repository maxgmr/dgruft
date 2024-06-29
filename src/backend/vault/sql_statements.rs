pub const SELECT_ACCOUNT: &str = "
    SELECT
        username,
        password_salt,
        dbl_hashed_password_hash,
        dbl_hashed_password_salt,
        encrypted_key_cipherbytes,
        encrypted_key_nonce
    FROM accounts
    WHERE
        username = ?1
";

pub const INSERT_ACCOUNT: &str = "
    INSERT INTO accounts (
        username,
        password_salt,
        dbl_hashed_password_hash,
        dbl_hashed_password_salt,
        encrypted_key_cipherbytes,
        encrypted_key_nonce
    )
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)
";

pub const DELETE_ACCOUNT: &str = "
    DELETE FROM accounts
    WHERE
        username = ?1
";

pub const UPDATE_ACCOUNT_PASSWORD_SALT: &str = "
    UPDATE accounts
    SET password_salt = ?1
    WHERE username = ?2
";

pub const UPDATE_ACCOUNT_DBL_HASHED_PASSWORD_HASH: &str = "
    UPDATE accounts
    SET dbl_hashed_password_hash = ?1
    WHERE username = ?2
";

pub const UPDATE_ACCOUNT_DBL_HASHED_PASSWORD_SALT: &str = "
    UPDATE accounts
    SET dbl_hashed_password_salt = ?1
    WHERE username = ?2
";

pub const UPDATE_ACCOUNT_ENCRYPTED_KEY_CIPHERBYTES: &str = "
    UPDATE accounts
    SET encrypted_key_cipherbytes = ?1
    WHERE username = ?2
";

pub const UPDATE_ACCOUNT_ENCRYPTED_KEY_NONCE: &str = "
    UPDATE accounts
    SET encrypted_key_nonce = ?1
    WHERE username = ?2
";

pub const SELECT_CREDENTIAL: &str = "
    SELECT
        owner_username,
        encrypted_name_cipherbytes,
        encrypted_name_nonce,
        encrypted_username_cipherbytes,
        encrypted_username_nonce,
        encrypted_password_cipherbytes,
        encrypted_password_nonce,
        encrypted_notes_cipherbytes,
        encrypted_notes_nonce
    FROM credentials
    WHERE
        owner_username = ?1
        AND encrypted_name_cipherbytes = ?2
";

pub const SELECT_ACCOUNT_CREDENTIALS: &str = "
    SELECT
        owner_username,
        encrypted_name_cipherbytes,
        encrypted_name_nonce,
        encrypted_username_cipherbytes,
        encrypted_username_nonce,
        encrypted_password_cipherbytes,
        encrypted_password_nonce,
        encrypted_notes_cipherbytes,
        encrypted_notes_nonce
    FROM credentials
    WHERE
        owner_username = ?1
";

pub const INSERT_CREDENTIAL: &str = "
    INSERT INTO credentials (
        owner_username,
        encrypted_name_cipherbytes,
        encrypted_name_nonce,
        encrypted_username_cipherbytes,
        encrypted_username_nonce,
        encrypted_password_cipherbytes,
        encrypted_password_nonce,
        encrypted_notes_cipherbytes,
        encrypted_notes_nonce
    )
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
";

pub const DELETE_CREDENTIAL: &str = "
    DELETE FROM credentials
    WHERE
        owner_username = ?1
        AND encrypted_name_cipherbytes = ?2
";

pub const UPDATE_CREDENTIAL_ENCRYPTED_USERNAME_CIPHERBYTES: &str = "
    UPDATE credentials
    SET encrypted_username_cipherbytes = ?1
    WHERE
        owner_username = ?2
        AND encrypted_name_cipherbytes = ?3
";

pub const UPDATE_CREDENTIAL_ENCRYPTED_USERNAME_NONCE: &str = "
    UPDATE credentials
    SET encrypted_username_nonce = ?1
    WHERE
        owner_username = ?2
        AND encrypted_name_cipherbytes = ?3
";

pub const UPDATE_CREDENTIAL_ENCRYPTED_PASSWORD_CIPHERBYTES: &str = "
    UPDATE credentials
    SET encrypted_password_cipherbytes = ?1
    WHERE
        owner_username = ?2
        AND encrypted_name_cipherbytes = ?3
";

pub const UPDATE_CREDENTIAL_ENCRYPTED_PASSWORD_NONCE: &str = "
    UPDATE credentials
    SET encrypted_password_nonce = ?1
    WHERE
        owner_username = ?2
        AND encrypted_name_cipherbytes = ?3
";

pub const UPDATE_CREDENTIAL_ENCRYPTED_NOTES_CIPHERBYTES: &str = "
    UPDATE credentials
    SET encrypted_notes_cipherbytes = ?1
    WHERE
        owner_username = ?2
        AND encrypted_name_cipherbytes = ?3
";

pub const UPDATE_CREDENTIAL_ENCRYPTED_NOTES_NONCE: &str = "
    UPDATE credentials
    SET encrypted_notes_nonce = ?1
    WHERE
        owner_username = ?2
        AND encrypted_name_cipherbytes = ?3
";

pub const SELECT_FILE_DATA: &str = "
    SELECT
        path,
        filename,
        owner_username,
        contents_nonce
    FROM files_data
    WHERE
        path = ?1
";

pub const SELECT_ACCOUNT_FILES_DATA: &str = "
    SELECT
        path,
        filename,
        owner_username,
        contents_nonce
    FROM files_data
    WHERE
        owner_username = ?1
";

pub const INSERT_FILE_DATA: &str = "
    INSERT INTO files_data (
        path,
        filename,
        owner_username,
        contents_nonce
    )
    VALUES (?1, ?2, ?3, ?4)
";

pub const DELETE_FILE_DATA: &str = "
    DELETE FROM files_data
    WHERE
        path = ?1
";

pub const UPDATE_FILE_DATA_CONTENTS_NONCE: &str = "
    UPDATE files_data
    SET contents_nonce = ?1
    WHERE path = ?2
";
