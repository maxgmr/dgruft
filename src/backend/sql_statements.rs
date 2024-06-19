pub const INSERT_NEW_ACCOUNT: &str = "
    INSERT INTO user_credentials (
        username,
        password_salt,
        dbl_hashed_password_hash,
        dbl_hashed_password_salt,
        encrypted_key_ciphertext,
        encrypted_key_nonce
    )
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)
";

pub const GET_ACCOUNT: &str = "
    SELECT
        username,
        password_salt,
        dbl_hashed_password_hash,
        dbl_hashed_password_salt,
        encrypted_key_ciphertext,
        encrypted_key_nonce
    FROM user_credentials
    WHERE username = ?1
";

pub const INSERT_NEW_PASSWORD: &str = "
    INSERT INTO passwords (
        encrypted_name,
        owner_username,
        encrypted_content,
        encrypted_notes,
        name_nonce,
        content_nonce,
        notes_nonce
    )
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
";

pub const GET_USER_PASSWORDS: &str = "
    SELECT
        encrypted_name,
        owner_username,
        encrypted_content,
        encrypted_notes,
        name_nonce,
        content_nonce,
        notes_nonce
    FROM passwords
    WHERE owner_username = ?1
";

pub const INSERT_NEW_FILE: &str = "
    INSERT INTO files (
        encrypted_path,
        owner_username,
        content_nonce,
        path_nonce
    )
    VALUES (?1, ?2, ?3, ?4)
";

pub const GET_USER_FILES: &str = "
    SELECT
        encrypted_path,
        owner_username,
        content_nonce,
        path_nonce
    FROM files
    WHERE owner_username = ?1
";
