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
}

/// Result type for github-auth operations.
pub type Result<T> = std::result::Result<T, Error>;
