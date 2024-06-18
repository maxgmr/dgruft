//! Functionality related to user configuration.
use color_eyre::eyre;
use directories::ProjectDirs;
use ratatui::style::Color;
use serde::Deserialize;
use std::{env, fs, io::ErrorKind, path::PathBuf};

const CONFIG_FILE_NAME: &str = "config.toml";

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
        Err(eyre::eyre!("ERROR: dgruft config directory not found."))
    }
}

/// The colour theme of the program. The default values are your terminal's default foreground and
/// background colours.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct Theme {
    /// Background colour.
    pub bg: Option<Color>,
    /// Background colour of the currently-focussed element.
    pub focus_bg: Option<Color>,
    /// Border colour.
    pub border: Option<Color>,
    /// Border colour of the currently-focussed element.
    pub focus_border: Option<Color>,
    /// Accent colour.
    pub accent: Option<Color>,
    /// Accent colour of the currently-focussed element.
    pub focus_accent: Option<Color>,
    /// Text colour.
    pub text: Option<Color>,
    /// Text colour of the currently-focussed element.
    pub focus_text: Option<Color>,
    /// Header colour.
    pub headers: Option<Color>,
    /// Header colour of the currently-focussed element.
    pub focus_headers: Option<Color>,
}

/// [Config] represents the values configurable by the user.
#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    /// `dgruft`'s colour theme.
    pub theme: Theme,
}
impl Config {
    /// Load the [Config] from the configuration files.
    pub fn load() -> eyre::Result<Self> {
        let config_file_path = get_config_dir()?.join(CONFIG_FILE_NAME);
        let config_file_content = match fs::read_to_string(&config_file_path) {
            Ok(file_content) => file_content,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Err(eyre::eyre!(format!(
                    "ERROR: Config file at path \"{}\" not found.",
                    config_file_path.display()
                )))
            }
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                return Err(eyre::eyre!(format!(
                    "ERROR: Permission denied for config file at path \"{}\".",
                    config_file_path.display()
                )))
            }
            Err(err) => return Err(eyre::eyre!(format!("ERROR: {}", err))),
        };

        match toml::from_str(&config_file_content) {
            Ok(config) => Ok(config),
            Err(err) => Err(eyre::eyre!(err)),
        }
    }
}
impl Default for Config {
    fn default() -> Self {
        Self {
            theme: Theme::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_load_config() {
        env::set_var("DGRUFT_CONFIG_DIRECTORY", "tests");
        let config = Config::load().unwrap();
        assert_eq!(config.theme.text.unwrap(), Color::Rgb(255, 255, 255));
    }
}
