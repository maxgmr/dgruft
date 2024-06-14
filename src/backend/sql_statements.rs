pub const SELECT_ALL_TABLES: &str = "
    SELECT name
    FROM sqlite_schema
    WHERE
        type='table' AND
        name NOT LIKE 'sqlite_%';
";

pub const CREATE_USER_CREDENTIALS: &str = "
    CREATE TABLE IF NOT EXISTS user_credentials (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        salt TEXT NOT NULL,
        hash_fn TEXT NOT NULL
    );
";

pub const INSERT_NEW_ACCOUNT: &str = "
    INSERT INTO user_credentials (username, password, salt, hash_fn)
    VALUES (?1, ?2, ?3, ?4)
";

pub const GET_ACCOUNT: &str = "
    SELECT username, password, salt, hash_fn
    FROM user_credentials
    WHERE username = ?1
";
