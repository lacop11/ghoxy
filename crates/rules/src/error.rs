use thiserror::Error;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum Error {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Config deserialization error: {0}")]
    DeserializationError(#[from] toml::de::Error),

    #[error("CEL parse errors: {0}")]
    CelParseError(#[from] cel::ParseErrors),

    #[error("Invalid github permisssions: {0}")]
    InvalidGithubPermissions(#[from] github_auth::Error),
}

/// Result type for rules operations.
pub type Result<T> = std::result::Result<T, Error>;
