use gcp_kms_sign::GcpKmsKeyVersion;

use crate::{Permissions, Result};

pub struct GithubTokenProviderOptions {
    pub app_client_id: String,
    pub app_private_key_kms_path: String,
}

pub struct GithubTokenProvider {
    options: GithubTokenProviderOptions,
    app_key_kms: GcpKmsKeyVersion,
    // TODO: token caches
}

impl GithubTokenProvider {
    pub async fn from_options(options: GithubTokenProviderOptions) -> Result<Self> {
        let app_key_kms = GcpKmsKeyVersion::new(&options.app_private_key_kms_path).await?;
        Ok(GithubTokenProvider {
            options,
            app_key_kms,
        })
    }

    // TODO: return token as wrapper which prevents logging
    pub async fn get_installation_access_token(&self, _permissions: Permissions) -> Result<String> {
        let jwt = self.create_signed_jwt().await?;
        println!("Created JWT: {}", jwt);
        todo!()
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
