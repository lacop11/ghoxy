use std::sync::Arc;

use gcp_kms_sign::GcpKmsKeyVersion;
use tracing::info;

use crate::{Permissions, Result, Error};
use token::Token;

pub struct GithubTokenProviderOptions {
    pub app_client_id: String,
    pub app_installation_id: String,
    pub app_key_kms: GcpKmsKeyVersion,
    pub user_agent: String,
}

pub struct GithubTokenProvider {
    options: GithubTokenProviderOptions,
    token_cache: moka::future::Cache<Permissions, Token>,
}

// Github promises token lifetime of one hour, can't be changed.
// Setting cache TTL much lower, the goal is to just reduct number of requests, eg. during
// TF provider request bursts, but not need to keep the token for the full hour.
const GITHUB_TOKEN_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5); //from_mins(5);

impl GithubTokenProvider {
    pub async fn from_options(options: GithubTokenProviderOptions) -> Result<Self> {
        // TODO: Validate app_installation_id is numeric
        Ok(GithubTokenProvider {
            options,
            token_cache: moka::future::Cache::builder()
                .time_to_live(GITHUB_TOKEN_CACHE_TTL)
                .build(),
        })
    }

    pub async fn get_installation_access_token(&self, permissions: &Permissions) -> Result<Token> {
        // Note: The Arc around errors is because the moka cache will coalesce multiple concurrent calls
        // here and only call create_installation_access_token once (which is great, we want that), so if
        // something fails the error must be shared by several callers. Sadly reqwest::Error and some other
        // libraries don't have Clone on error types so we have to do manual map_err(Arc::new) in few places.
        self.token_cache.try_get_with_by_ref(
            permissions,
            self.create_installation_access_token(permissions),
        ).await.map_err(Arc::unwrap_or_clone)
    }

    async fn create_installation_access_token(
        &self,
        permissions: &Permissions,
    ) -> Result<Token> {
        info!("Creating new installation access token with permissions: {:?}", permissions);
        // Create new JWT token signed by the KMS. We could cache this too, but this function
        // is only called if we don't have a cached installation token, so there is already
        // one layer of caching on top of this, no need to cache the JWT separately.
        let jwt = self.create_signed_jwt().await?;

        // Exchange the JWT for an installation access token.
        // https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app
        let client = reqwest::Client::new();
        let response = client
            .post(format!(
                // TODO: replace with github base url from options
                "https://api.github.com/app/installations/{}/access_tokens",
                self.options.app_installation_id
            ))
            .bearer_auth(jwt.get_sensitive_value())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", &self.options.user_agent)
            .json(&serde_json::json!({
                "permissions": permissions.to_json_map(),
            }))
            .send()
            .await
            .map_err(Arc::new)?;

        #[derive(Debug, serde::Deserialize)]
        struct InstallationTokenResponse {
            token: String,
            expires_at: chrono::DateTime<chrono::Utc>,
        }

        if !response.status().is_success() {
            return Err(Error::GithubTokenRequestFailed(
                response.status().as_u16(),
                response.text().await.map_err(Arc::new)?,
            ));
        }

        let response: InstallationTokenResponse = response.json().await.map_err(Arc::new)?;

        // Make sure the lifetime is at least twice the cache TTL, to avoid
        // caching tokens that are about to expire. We cache for lot shorter
        // than what github promises, so this should never happen, but better
        // to get an explicit error than weird behavior.
        let token_lifetime = response.expires_at - chrono::Utc::now();
        if token_lifetime < chrono::Duration::from_std(GITHUB_TOKEN_CACHE_TTL * 2).expect("won't fail") {
            return Err(Error::GithubTokenDurationTooShort(token_lifetime));
        }

        Ok(Token::new(response.token))
    }

    // TODO: Isn't it weird this doesn't have any nonce or something?
    /// Constructs a JWT signed using our Github App private key.
    /// This can then be exchanged for installation access token using Github API.
    /// Reference: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
    async fn create_signed_jwt(&self) -> Result<Token> {
        // TODO: The jsonwebtoken crate only supports keys that are directly passed in, not as KMS / sign callback.
        // Consider contributing support for that (eg. add `asymmetric_sign_with` that takes a closure or trait object).
        // Until then we construct the JWT manually, it's not that hard.

        // Github requires we use RS256 tokens.
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);

        #[derive(serde::Serialize)]
        struct GithubAppJwtClaims {
            iss: String,
            iat: u64,
            exp: u64,
        }
        let now = std::time::SystemTime::now();
        let claims = GithubAppJwtClaims {
            // Issuer should be app's client id.
            iss: self.options.app_client_id.clone(),
            // Github recommends to set this 60 seconds in the past to avoid clock drift issues.
            iat: unix_seconds_at(
                now.checked_sub(std::time::Duration::from_secs(60))
                    .expect("Should never underflow"),
            ),
            // Maximum 10 minutes in the future, default to 5 minutes.
            // TODO: Maybe this should be part of options?
            exp: unix_seconds_at(
                now.checked_add(std::time::Duration::from_secs(300))
                    .expect("Should never overflow"),
            ),
        };

        let partial_jwt = format!(
            "{}.{}",
            base64_url_encoded(&serde_json::to_vec(&header).map_err(Arc::new)?),
            base64_url_encoded(&serde_json::to_vec(&claims).map_err(Arc::new)?),
        );
        let signature = self
            .options.app_key_kms
            .asymmetric_sign(partial_jwt.as_bytes())
            .await.map_err(Arc::new)?;
        let signed_jwt = format!("{}.{}", partial_jwt, base64_url_encoded(&signature),);
        Ok(Token::new(signed_jwt))
    }
}

fn unix_seconds_at(time: std::time::SystemTime) -> u64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .expect("Should never be before unix epoch")
        .as_secs()
}

fn base64_url_encoded(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
