pub const CREATE_USER_CREDENTIALS: &str = "
    CREATE TABLE IF NOT EXISTS user_credentials (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        salt TEXT NOT NULL,
        hash_fn TEXT NOT NULL
    );
";
