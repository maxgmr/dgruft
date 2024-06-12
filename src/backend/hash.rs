use sha2::Sha256;

/// The possible hash functions that dgruft can use.
pub enum HashFn {
    /// SHA-256 from [sha2] crate.
    Sha256,
}
