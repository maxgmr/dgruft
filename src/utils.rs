//! General utilities used by `dgruft`.
use std::env;

use camino::Utf8PathBuf;
use color_eyre::eyre::{self, eyre};
use directories::ProjectDirs;

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

/// Get the directory of a particular `drguft` account's files.
pub fn account_dir<S>(username: S) -> eyre::Result<Utf8PathBuf>
where
    S: AsRef<str>,
{
    let mut data_dir = data_dir()?;
    data_dir.push(username.as_ref());
    Ok(data_dir)
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
