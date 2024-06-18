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

