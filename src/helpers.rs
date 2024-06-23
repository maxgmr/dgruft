//! Small, general helper functions.
use std::{env, path::PathBuf};

use base64ct::{Base64, Encoding};
use directories::ProjectDirs;
use regex::Regex;

use crate::error::Error;

const VERSION_MESSAGE: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " -",
    env!("VERGEN_GIT_DESCRIBE"),
    " (",
    env!("VERGEN_BUILD_DATE"),
    ")"
);

/// Get the version of the program as a string.
pub fn version() -> String {
    let author = clap::crate_authors!();
    format!(
        "\
{VERSION_MESSAGE}

Author: {author}

Data Directory: {}
Config Directory: {}",
        get_data_dir().display(),
        get_config_dir().display(),
    )
}

/// Get the directory of this project,
pub fn project_directory() -> Option<ProjectDirs> {
    ProjectDirs::from("ca", "maxgmr", env!("CARGO_PKG_NAME"))
}

/// Get the crate name in all caps as a string.
pub fn project_name() -> String {
    env!("CARGO_CRATE_NAME").to_uppercase().to_string()
}

/// Get the environment variable name that can be set to change the data folder location.
pub fn data_folder_env_var_name() -> Option<PathBuf> {
    env::var(format!("{}_DATA", project_name().clone()))
        .ok()
        .map(PathBuf::from)
}

/// Get the environment variable name that can be set to change the config folder location.
pub fn config_folder_env_var_name() -> Option<PathBuf> {
    env::var(format!("{}_CONFIG", project_name().clone()))
        .ok()
        .map(PathBuf::from)
}

/// Get the log file name.
pub fn log_file_name() -> String {
    format!("{}.log", env!("CARGO_PKG_NAME"))
}

/// Get the directory where program data is stored.
pub fn get_data_dir() -> PathBuf {
    if let Some(path_buf) = data_folder_env_var_name().clone() {
        path_buf
    } else if let Some(proj_dirs) = project_directory() {
        proj_dirs.data_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".data")
    }
}

/// Get the directory where configuration files are stored.
pub fn get_config_dir() -> PathBuf {
    if let Some(path_buf) = config_folder_env_var_name().clone() {
        path_buf
    } else if let Some(proj_dirs) = project_directory() {
        proj_dirs.config_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".config")
    }
}

/// Return `true` iff the input string is parseable as a standard base 64-encoded string.
pub fn is_base64(string: &str) -> bool {
    let base64_re =
        Regex::new(r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$").unwrap();
    base64_re.captures(string).is_some()
}

/// Convert bytes to base 64 string.
pub fn bytes_to_b64(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

/// Convert base 64 string to bytes.
pub fn b64_to_bytes(str: &str) -> Result<Vec<u8>, Error> {
    match Base64::decode_vec(str) {
        Ok(bytes) => Ok(bytes),
        Err(base64ct::Error::InvalidEncoding) => Err(Error::InvalidB64Error(str.to_owned())),
        Err(e) => Err(Error::UnhandledError(e.to_string())),
    }
}

/// Convert base 64 string to fixed length byte array.
pub fn b64_to_fixed<T, const LEN: usize>(src: T, debug_name: &str) -> Result<[u8; LEN], Error>
where
    T: AsRef<[u8]> + ToString,
{
    let mut output = [0u8; LEN];

    // Get actual length of src in bytes
    let actual_length = if let Ok(vec) = Base64::decode_vec(&src.to_string()) {
        if vec.len() != LEN {
            // Length does not match exactly; return error
            return Err(Error::InvalidLengthB64Error(
                String::from(debug_name),
                LEN,
                vec.len(),
            ));
        } else {
            vec.len()
        }
    } else {
        // Malformed b64 string
        return Err(Error::InvalidB64Error(src.to_string().to_owned()));
    };

    // Length OK; fill up output array with bytes read from src.
    match Base64::decode(&src, &mut output) {
        Ok(_) => (),
        Err(base64ct::Error::InvalidLength) => {
            return Err(Error::InvalidLengthB64Error(
                String::from(debug_name),
                LEN,
                actual_length,
            ));
        }
        Err(base64ct::Error::InvalidEncoding) => {
            return Err(Error::InvalidB64Error(src.to_string().to_owned()));
        }
    };

    Ok(output)
}

/// Convert bytes to UTF-8 string.
pub fn bytes_to_utf8(bytes: &[u8], debug_name: &str) -> Result<String, Error> {
    match std::str::from_utf8(bytes) {
        Ok(utf8) => Ok(utf8.to_owned()),
        Err(_) => Err(Error::Utf8FromBytesError(String::from(debug_name))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const EXAMPLE_BYTES: [u8; 8] = [84_u8, 104_u8, 101_u8, 32_u8, 113_u8, 117_u8, 105_u8, 99_u8];
    const EXAMPLE_B64STR: &str = "VGhlIHF1aWM=";
    const EXAMPLE_B64STR7: &str = "VGhlIHF1aQ==";

    #[test]
    fn test_b64tf() {
        let bytes: [u8; 8] = b64_to_fixed::<&str, 8>(EXAMPLE_B64STR, "bytes").unwrap();
        assert_eq!(bytes, EXAMPLE_BYTES);
    }

    #[test]
    fn test_b64tf_bad_b64() {
        let bytes =
            b64_to_fixed::<String, 8>(String::from(&EXAMPLE_B64STR[1..]), "bytes").unwrap_err();
        if let Error::InvalidB64Error(input_string) = bytes {
            assert_eq!(input_string, &EXAMPLE_B64STR[1..]);
        } else {
            dbg!(&bytes);
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_b64tf_bad_len() {
        let bytes = b64_to_fixed::<String, 8>(String::from(EXAMPLE_B64STR7), "bytes").unwrap_err();
        if let Error::InvalidLengthB64Error(debug_str, expected_len, actual_len) = bytes {
            assert_eq!(debug_str, "bytes");
            assert_eq!(expected_len, 8);
            assert_eq!(actual_len, 7);
        } else {
            dbg!(&bytes);
            panic!("Wrong error type");
        }
    }
}
