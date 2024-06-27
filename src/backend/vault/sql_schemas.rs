pub const CREATE_ACCOUNTS: &str = "
CREATE TABLE IF NOT EXISTS accounts (
    username TEXT PRIMARY KEY,
    password_salt TEXT NOT NULL,
    dbl_hashed_password_hash TEXT NOT NULL,
    dbl_hashed_password_salt TEXT NOT NULL,
    encrypted_key_cipherbytes TEXT NOT NULL,
    encrypted_key_nonce TEXT NOT NULL
)
";

pub const CREATE_CREDENTIALS: &str = "
CREATE TABLE IF NOT EXISTS credentials (
    owner_username TEXT NOT NULL,
    encrypted_name_cipherbytes TEXT NOT NULL,
    encrypted_name_nonce TEXT NOT NULL,
    encrypted_username_cipherbytes TEXT NOT NULL,
    encrypted_username_nonce TEXT NOT NULL,
    encrypted_password_cipherbytes TEXT NOT NULL,
    encrypted_password_nonce TEXT NOT NULL,
    encrypted_notes_cipherbytes TEXT NOT NULL,
    encrypted_notes_nonce TEXT NOT NULL,
    FOREIGN KEY (owner_username)
        REFERENCES accounts(username)
        ON DELETE CASCADE,
    PRIMARY KEY(owner_username, encrypted_name_cipherbytes)
)
";

pub const CREATE_FILES_DATA: &str = "
CREATE TABLE IF NOT EXISTS files_data (
    path TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    owner_username TEXT NOT NULL,
    content_nonce TEXT NOT NULL,
    FOREIGN KEY (owner_username)
        REFERENCES accounts(username)
        ON DELETE CASCADE
)
";
