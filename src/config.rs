//! All functionality related to user customisation of `dgruft`.
use color_eyre::eyre;

/// All the user-defined options.
#[derive(Debug, Default)]
pub struct Config {}
impl Config {
    pub fn new() -> eyre::Result<Self> {
        // TODO
        Ok(Config {})
    }
}
