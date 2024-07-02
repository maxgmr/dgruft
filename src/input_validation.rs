//! Different helpers, structs, and consts for user input validation.
use color_eyre::eyre::{self, eyre};

/// Ensure that the given [String] satisfies the given restrictions.
pub fn validate_input(
    input: String,
    min_len: usize,
    max_len: usize,
    forbidden_chars: &str,
) -> eyre::Result<()> {
    if input.len() < min_len {
        Err(eyre!(
            "Input length {} is less than minimum length {}.",
            input.len(),
            min_len
        ))
    } else if input.len() > max_len {
        Err(eyre!(
            "Input length {} is greater than maximum length {}.",
            input.len(),
            max_len
        ))
    } else {
        for f_char in forbidden_chars.chars() {
            for i_char in input.chars() {
                if i_char == f_char {
                    return Err(eyre!("Input cannot contain character '{}'.", i_char));
                }
            }
        }
        Ok(())
    }
}
