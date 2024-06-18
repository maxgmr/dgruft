//! Functionality related to user configuration.
use color_eyre::eyre::{self, WrapErr};
use directories::ProjectDirs;
use std::{env, path::PathBuf};

/// Retrieve the [PathBuf] to the location of `dgruft`'s config directory.
///
/// Set the DGRUFT_CONFIG_DIRECTORY environment variable to select a custom location for this.
///
/// Default: follows the XDG Base Directory Specification.
pub fn get_config_dir() -> eyre::Result<PathBuf> {
    if let Ok(env_var_path) = env::var("DGRUFT_CONFIG_DIRECTORY") {
        Ok(PathBuf::from(env_var_path))
    } else if let Some(project_dirs) = ProjectDirs::from("ca", "maxgmr", "dgruft") {
        Ok(project_dirs.config_local_dir().to_path_buf())
    } else {
        Err(eyre::eyre!("dgruft config directory not found."))
    }
}
