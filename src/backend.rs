//! All backend functionality.
mod account;
mod credential;
mod encryption;
mod file_data;
mod hashing;
mod vault;

// Re-imports.
pub use account::{Account, UnlockedAccount};
pub use credential::Credential;
pub use encryption::{
    encrypted::{Aes256Key, Aes256Nonce, Encrypted},
    traits::{TryFromEncrypted, TryIntoEncrypted},
};
pub use file_data::FileData;
pub use hashing::hashed::{Hash, Hashed, Salt};
pub use vault::Vault;
