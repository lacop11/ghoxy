use thiserror::Error;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum ProxyError {
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

    #[error("Unsupported HTTP method: {0}")]
    UnsupportedHttpMethod(String),
    #[error("Unsupported GraphQL method")]
    UnsupportedGraphqlMethod,

    #[error("Request not allowed by rule")]
    RequestNotAllowedByRule,

    #[error("Github token provider error: {0}")]
    GithubTokenProviderError(#[from] github_auth::Error),

    #[error("HTTP client error: {0}")]
    HttpClientError(#[from] reqwest::Error),
    #[error("HTTP response error: {0}")]
    HttpResponseError(#[from] axum::http::Error),
}

/// Result type for proxy operations.
pub type ProxyResult<T> = std::result::Result<T, ProxyError>;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum ServerError {
    #[error("Proxy error: {0}")]
    ProxyError(#[from] ProxyError),

    #[error("Client auth validator error: {0}")]
    ClientAuthValidatorError(#[from] client_auth::Error),

    #[error("Github token provider error: {0}")]
    GithubTokenProviderError(#[from] github_auth::Error),

    #[error("GCP KMS error: {0}")]
    GcpKmsKeyError(#[from] gcp_kms_sign::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result type for server operations.
pub type ServerResult<T> = std::result::Result<T, ServerError>;
