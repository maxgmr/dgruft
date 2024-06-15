pub const SELECT_ALL_TABLES: &str = "
    SELECT name
    FROM sqlite_schema
    WHERE
        type='table' AND
        name NOT LIKE 'sqlite_%';
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
