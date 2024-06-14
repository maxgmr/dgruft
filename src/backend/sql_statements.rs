pub const DROP_TABLE: &str = "
    DROP TABLE IF EXISTS {}
";

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
