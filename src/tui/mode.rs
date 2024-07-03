//! All the different "modes"/"screens" the TUI can be in.

#[derive(Debug, Default, Eq, PartialEq)]
pub enum Mode {
    #[default]
    Login,
}
