//! All functionality related to the [sqlite] database dgruft uses for persistence.
use sqlite::Connection;
use std::ffi::OsStr;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

/// Connection interface to the database.
pub struct Database {
    /// Path to .db file
    path: PathBuf,
    /// SQLite database connection
    connection: Connection,
}
impl Database {
    /// Open a new connection to the database at the given path.
    pub fn connect<P>(path: P) -> std::io::Result<Self>
    where
        P: AsRef<Path> + AsRef<OsStr>,
    {
        let opened = sqlite::open(&path);
        match opened {
            Ok(connection) => Ok(Self {
                path: PathBuf::from(&path),
                connection,
            }),
            Err(e) => Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "{} {}",
                    e.code.unwrap_or(0_isize),
                    e.message.unwrap_or("".to_owned())
                ),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn setup() -> Database {
        let db = Database::connect("./dbs/dgruft-test.db").unwrap();
        db
    }

    #[test]
    fn test_connect() {
        setup();
    }
}
