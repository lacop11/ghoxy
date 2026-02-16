use thiserror::Error;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Invalid request path")]
    InvalidRequestPath,

    #[error("Invalid rules: {0}")]
    InvalidRules(#[from] rules::Error),

    #[error("No such rule: {0}")]
    NoSuchRule(String),

    #[error("Token validation error: {0}")]
    TokenValidationError(#[from] client_auth::Error),

    #[error("Missing authorization header")]
    MissingAuthorizationHeader,
    #[error("Invalid authorization header")]
    InvalidAuthorizationHeader,
}

/// Result type for proxy operations.
pub type Result<T> = std::result::Result<T, Error>;
