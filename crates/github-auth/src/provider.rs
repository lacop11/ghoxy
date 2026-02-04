use gcp_kms_sign::GcpKmsKeyVersion;

use crate::{Permissions, Result};

pub struct GithubTokenProviderOptions {
    pub app_client_id: String,
    pub app_installation_id: String,
    pub app_private_key_kms_path: String,
}

pub struct GithubTokenProvider {
    options: GithubTokenProviderOptions,
    app_key_kms: GcpKmsKeyVersion,
    // TODO: token caches, keyed by permissions, should store expiration time so if too short we can refresh
}

impl GithubTokenProvider {
    pub async fn from_options(options: GithubTokenProviderOptions) -> Result<Self> {
        // TODO: Validate app_installation_id is numeric
        let app_key_kms = GcpKmsKeyVersion::new(&options.app_private_key_kms_path).await?;
        Ok(GithubTokenProvider {
            options,
            app_key_kms,
        })
    }

    // TODO: return token as wrapper which prevents logging
    pub async fn get_installation_access_token(&self, _permissions: Permissions) -> Result<String> {
        // TODO: caching logic, this should only be called when we don't have a valid one or it
        // is expiring soon, and have to store the response + block multiple concurrent calls for the
        // same set of permissions to only do one request.
        let (token, _expires_at) = self.create_installation_access_token().await?;
        Ok(token)
    }

    // TODO: return token as wrapper which prevents logging
    async fn create_installation_access_token(
        &self,
    ) -> Result<(String, chrono::DateTime<chrono::Utc>)> {
        // Create new JWT token. We could cache this too, but this function is only called if we
        // don't have a cached installation token, so there is already one layer of caching on
        // top of this, no need to cache the JWT separately.
        let jwt = self.create_signed_jwt().await?;

        // Exchange the JWT for an installation access token.
        // Lifetime can't be controlled, it's always one hour.
        // https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app

        let client = reqwest::Client::new();
        let response = client
            .post(format!(
                "https://api.github.com/app/installations/{}/access_tokens",
                self.options.app_installation_id
            ))
            .bearer_auth(jwt.as_str())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            // TODO: make this repo path or something
            .header("User-Agent", "gaap")
            .send()
            .await?;
        // TODO body with permissions

        #[derive(Debug, serde::Deserialize)]
        struct InstallationTokenResponse {
            token: String,
            expires_at: chrono::DateTime<chrono::Utc>,
        }

        if response.status().is_success() {
            let response: InstallationTokenResponse = response.json().await?;
            return Ok((response.token, response.expires_at));
        }

        Err(crate::Error::GithubTokenRequestFailed(
            response.status().as_u16(),
            response.text().await?,
        ))
    }

    // TODO: Isn't it weird this doesn't have any nonce or something?
    // TODO: Wrap in Token type too
    /// Constructs a JWT signed using our Github App private key.
    /// This can then be exchanged for installation access token using Github API.
    /// Reference: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
    async fn create_signed_jwt(&self) -> Result<String> {
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
            base64_url_encoded(&serde_json::to_vec(&header)?),
            base64_url_encoded(&serde_json::to_vec(&claims)?),
        );
        let signature = self
            .app_key_kms
            .asymmetric_sign(partial_jwt.as_bytes())
            .await?;
        let signed_jwt = format!("{}.{}", partial_jwt, base64_url_encoded(&signature),);
        Ok(signed_jwt)
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
