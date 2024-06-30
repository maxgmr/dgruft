//! General utilities used by `dgruft`.
use std::{
    env,
    fs::{self, File},
};

use camino::Utf8PathBuf;
use color_eyre::eyre::{self, eyre};
use directories::ProjectDirs;

/// The name of the `dgruft` SQLite database.
const DB_NAME: &str = "dgruft.db";

/// String displaying the package version, git info, and build date of `dgruft`.
const VERSION_MESSAGE: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " -",
    env!("VERGEN_GIT_DESCRIBE"),
    " (",
    env!("VERGEN_BUILD_DATE"),
    ")"
);

/// Get the version, author info, and directories of `dgruft`.
pub fn info() -> String {
    let author = clap::crate_authors!();
    format!(
        "\
{VERSION_MESSAGE}

Author: {author}

Data Directory: {}
Config Directory: {}",
        data_dir().unwrap(),
        config_dir().unwrap(),
    )
}

/// Set up `dgruft` on first-time startup.
pub fn setup() -> eyre::Result<()> {
    // Create the directory where `dgruft` program data is stored.
    if fs::metadata(data_dir()?).is_err() {
        fs::create_dir_all(data_dir()?)?;
    }

    // Create the directory where `dgruft` configuration data is stored.
    if fs::metadata(config_dir()?).is_err() {
        fs::create_dir_all(config_dir()?)?;
    }

    // Create the `dgruft` SQLite database file.
    if fs::metadata(db_path()?).is_err() {
        File::create_new(db_path()?)?;
    }

    Ok(())
}

/// Get the path to the `dgruft` database.
pub fn db_path() -> eyre::Result<Utf8PathBuf> {
    let mut db_path = data_dir()?;
    db_path.push(DB_NAME);
    Ok(db_path)
}

/// Get the directory where `dgruft` program data is stored.
pub fn data_dir() -> eyre::Result<Utf8PathBuf> {
    if let Some(utf8_path_buf) = data_dir_env_var() {
        // Prioritise user-set path.
        Ok(utf8_path_buf)
    } else if let Some(proj_dirs) = project_directory() {
        // Next priority: XDG-standardised local dir.
        match Utf8PathBuf::from_path_buf(proj_dirs.data_local_dir().to_path_buf()) {
            Ok(utf8_path_buf) => Ok(utf8_path_buf),
            Err(path_buf) => Err(eyre!(
                "Path to data directory {:?} contains non-UTF-8 content.",
                path_buf
            )),
        }
    } else {
        // Last priority: .config folder relative to CWD
        Ok(Utf8PathBuf::from(".").join(".config"))
    }
}

/// Get the directory where `dgruft` configuration data is stored.
pub fn config_dir() -> eyre::Result<Utf8PathBuf> {
    if let Some(utf8_path_buf) = data_dir_env_var() {
        // Prioritise user-set path.
        Ok(utf8_path_buf)
    } else if let Some(proj_dirs) = project_directory() {
        // Next priority: XDG-standardised local dir.
        match Utf8PathBuf::from_path_buf(proj_dirs.config_local_dir().to_path_buf()) {
            Ok(utf8_path_buf) => Ok(utf8_path_buf),
            Err(path_buf) => Err(eyre!(
                "Path to data directory {:?} contains non-UTF-8 content.",
                path_buf
            )),
        }
    } else {
        // Last priority: .config folder relative to CWD
        Ok(Utf8PathBuf::from(".").join(".config"))
    }
}

/// Get the log file name.
pub fn log_file_name() -> String {
    format!("{}.log", env!("CARGO_PKG_NAME"))
}

/// Data directory environment variable. Can be set to change the location of the `dgruft` data
/// directory.
pub fn data_dir_env_var() -> Option<Utf8PathBuf> {
    get_env_var_path("DATA")
}

/// Config directory environment variable. Can be used to change the location of the `dgruft` data
/// directory.
pub fn config_dir_env_var() -> Option<Utf8PathBuf> {
    get_env_var_path("CONFIG")
}

// Helper function.
fn get_env_var_path(suffix: &str) -> Option<Utf8PathBuf> {
    env::var(format!("{}_{}", crate_name_constant_case(), suffix))
        .ok()
        .map(Utf8PathBuf::from)
}

/// Get the crate name in CONSTANT_CASE.
pub fn crate_name_constant_case() -> String {
    env!("CARGO_CRATE_NAME").to_uppercase().to_string()
}

/// Get the directory of this project.
pub fn project_directory() -> Option<ProjectDirs> {
    ProjectDirs::from("ca", "maxgmr", env!("CARGO_PKG_NAME"))
}
