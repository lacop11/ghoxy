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

    #[error("CEL serialization error: {0}")]
    CelSerializationError(#[from] cel::SerializationError),

    #[error("Invalid CEL value: {0:?}, expected bool")]
    InvalidCelValue(cel::Value),

    #[error("CEL execution error: {0}")]
    CelExecutionError(#[from] cel::ExecutionError),

    #[error("Ambiguous rule: multiple rules match the same request")]
    AmbiguousRule,
}

/// Result type for rules operations.
pub type Result<T> = std::result::Result<T, Error>;
