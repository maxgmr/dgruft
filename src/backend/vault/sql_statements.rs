pub const GET_ACCOUNT: &str = "
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

pub const GET_CREDENTIAL: &str = "
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

pub const GET_FILE_DATA: &str = "
    SELECT
        path,
        filename,
        owner_username,
        content_nonce,
    FROM files_data
    WHERE
        path = ?1
";
