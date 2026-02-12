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
}

/// Result type for proxy operations.
pub type Result<T> = std::result::Result<T, Error>;
