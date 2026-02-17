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
pub type Result<T> = std::result::Result<T, Error>;
