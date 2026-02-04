use thiserror::Error;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum Error {
    #[error("GCP KMS error: {0}")]
    KmsError(#[from] gcp_kms_sign::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("HTTP request error: {0}")]
    HttpRequestError(#[from] reqwest::Error),

    #[error("Github token request failed with status code: {0}, message: {1}")]
    GithubTokenRequestFailed(u16, String),

    #[error("No permissions specified, for security reasons all token requests must specify all requested permissions explicitly")]
    EmptyPermissions,

    #[error("Invalid permission requested: {0}")]
    InvalidPermission(String),

    #[error("Duplicate permission scope requested: {0}")]
    DuplicatePermissionScope(String),
}

/// Result type for github-auth operations.
pub type Result<T> = std::result::Result<T, Error>;
