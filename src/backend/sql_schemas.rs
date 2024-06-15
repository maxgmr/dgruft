pub const CREATE_USER_CREDENTIALS: &str = "
    CREATE TABLE IF NOT EXISTS user_credentials (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        salt TEXT NOT NULL,
        hash_fn TEXT NOT NULL
    );
";

pub const CREATE_PASSWORDS: &str = "
    CREATE TABLE IF NOT EXISTS passwords (
        encrypted_password TEXT NOT NULL,
        context TEXT NOT NULL,
        owner_username TEXT NOT NULL,
        FOREIGN KEY (owner_username)
            REFERENCES user_credentials(username)
            ON DELETE CASCADE,
        PRIMARY KEY(encrypted_password, context, owner_username)
    )
";
