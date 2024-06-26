pub const CREATE_USER_CREDENTIALS: &str = "
    CREATE TABLE IF NOT EXISTS user_credentials (
        username TEXT PRIMARY KEY,
        password_salt TEXT NOT NULL,
        dbl_hashed_password_hash TEXT NOT NULL,
        dbl_hashed_password_salt TEXT NOT NULL,
        encrypted_key_ciphertext TEXT NOT NULL,
        encrypted_key_nonce TEXT NOT NULL
    );
";

pub const CREATE_PASSWORDS: &str = "
    CREATE TABLE IF NOT EXISTS passwords (
        owner_username TEXT NOT NULL,
        encrypted_name TEXT NOT NULL,
        encrypted_username TEXT NOT NULL,
        encrypted_content TEXT NOT NULL,
        encrypted_notes TEXT NOT NULL,
        username_nonce TEXT NOT NULL,
        name_nonce TEXT NOT NULL,
        content_nonce TEXT NOT NULL,
        notes_nonce TEXT NOT NULL,
        FOREIGN KEY (owner_username)
            REFERENCES user_credentials(username)
            ON DELETE CASCADE,
        PRIMARY KEY(owner_username, encrypted_name)
    )
";

pub const CREATE_FILES: &str = "
    CREATE TABLE IF NOT EXISTS files (
        path TEXT NOT NULL PRIMARY KEY,
        name TEXT NOT NULL,
        owner_username TEXT NOT NULL,
        content_nonce TEXT NOT NULL,
        FOREIGN KEY (owner_username)
            REFERENCES user_credentials(username)
            ON DELETE CASCADE
    )
";
