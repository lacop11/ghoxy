use thiserror::Error;

#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Invalid JWT: {0}")]
    InvalidJwt(#[from] jsonwebtoken::errors::Error),

    #[error("Token header is missing 'kid'")]
    TokenMissingKid,

    #[error("Issuer is not allowed: {0}")]
    IssuerNotAllowed(String),

    #[error("Signing key not found for kid: {0}")]
    SigningKeyNotFound(String),

    #[error("JWKS fetch error: {0}")]
    JwksFetchError(#[from] jwks::JwksError),

    #[error("Token claim field missing or invalid: {0}")]
    TokenClaimMissingOrInvalid(&'static str),
}

/// Result type for client-auth operations.
pub type Result<T> = std::result::Result<T, Error>;
