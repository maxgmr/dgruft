//! Small, general helper functions.
use regex::Regex;

/// Return `true` iff the input string is parseable as a standard base 64-encoded string.
pub fn is_base64(string: &str) -> bool {
    let base64_re =
        Regex::new(r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$").unwrap();
    base64_re.captures(string).is_some()
}
