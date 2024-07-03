mod login;
mod logo;

// Re-exports
pub use login::Login;
pub use logo::Logo;

/// A GUI component that can render things, send, and receive signals.
pub trait Component {}
