use token::Token;

use crate::Result;

/// Token provider for GCP authentication.
///
/// Trivial wrapper around `gcp_auth::TokenProvider` that let's us implement a mock provider for testing.
#[async_trait::async_trait]
pub trait TokenProvider {
    /// Get GCP auth token for given scopes.
    ///
    /// Same semantics as `gcp_auth::TokenProvider::token`.
    async fn token(&self, scopes: &[&str]) -> Result<Token>;
}

pub(crate) struct RealTokenProvider(std::sync::Arc<dyn gcp_auth::TokenProvider>);

impl RealTokenProvider {
    pub(crate) async fn new() -> Result<Self> {
        Ok(RealTokenProvider(gcp_auth::provider().await?))
    }
}

#[async_trait::async_trait]
impl TokenProvider for RealTokenProvider {
    async fn token(&self, scopes: &[&str]) -> Result<Token> {
        let token = self.0.token(scopes).await?;
        Ok(Token::new(token.as_str().to_string()))
    }
}
