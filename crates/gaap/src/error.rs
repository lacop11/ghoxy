use thiserror::Error;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Invalid request path")]
    InvalidRequestPath,
}

/// Result type for proxy operations.
pub type Result<T> = std::result::Result<T, Error>;
