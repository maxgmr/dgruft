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

pub const GET_FILE_DATA: &str = "
    SELECT
        path,
        filename,
        owner_username,
        content_nonce
    FROM files_data
    WHERE
        path = ?1
";

pub const INSERT_FILE_DATA: &str = "
    INSERT INTO files_data (
        path,
        filename,
        owner_username,
        content_nonce
    )
    VALUES (?1, ?2, ?3, ?4)
";

pub const DELETE_FILE_DATA: &str = "
    DELETE FROM files_data
    WHERE
        path = ?1
";
