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

    #[error("Invalid REST method: {0}")]
    InvalidRestMethod(#[from] http::method::InvalidMethod),

    #[error("REST method not allowed: {0}")]
    RestMethodNotAllowed(http::Method),

    #[error("Regex parse error: {0}")]
    RegexParseError(#[from] regex::Error),
    #[error("Regex is explictly anchored, remove ^/$, it is always added automatically")]
    RegexExplicitlyAnchored,

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

    #[error("Invalid rule: Empty path list")]
    EmptyPathList,
    #[error("Invalid rule: Empty method list")]
    EmptyMethodList,
    #[error("Invalid rule: No REST or GraphQL rules specified")]
    NoRulesSpecified,

    #[error("Rule directory must only contain files named rule-name.toml")]
    InvalidRuleDirectoryEntry,
}

/// Result type for rules operations.
pub type Result<T> = std::result::Result<T, Error>;
