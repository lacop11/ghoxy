//! Github authentication.

mod permissions;
pub use permissions::Permissions;

mod provider;
pub use provider::{GithubTokenProvider, GithubTokenProviderOptions};

mod error;
pub use error::{Error, Result};
