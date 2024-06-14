//! Small, general helper functions.
use regex::Regex;

pub fn is_base64(string: &str) -> bool {
    let base64_re =
        Regex::new(r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$").unwrap();
    if let Some(_) = base64_re.captures(string) {
        true
    } else {
        false
    }
}
