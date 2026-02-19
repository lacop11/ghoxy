use std::{collections::HashMap, sync::Arc};

use crate::{Claims, Error, Result};

/// Options for configuring a TokenValidator.
pub struct TokenValidatorOptions {
    /// The expected audience (`aud` claim) in the token.
    pub expected_audience: String,
    /// List of allowed issuers. These must match the `iss` claim in the token.
    pub allowed_issuers: Vec<String>,
    /// Clock skew leeway in seconds when validation token `iat`/`exp`/`nbf` timestamps.
    pub token_age_leeway_seconds: u32,
}

/// Validates JWT tokens using JWKS from allowed issuers.
///
/// Maintains a cache of JWKS for each allowed issuer, which must be
/// periodically updated by calling `update_jwks`.
pub struct TokenValidator {
    options: TokenValidatorOptions,
    cached_jwks: HashMap<String, Arc<tokio::sync::RwLock<Option<jwks::Jwks>>>>,
}

impl TokenValidator {
    /// Creates a new TokenValidator with the provided options.
    ///
    /// Does not fetch JWKS automatically, `update_jwks` must be called separately.
    pub fn from_options(options: TokenValidatorOptions) -> Self {
        let mut cached_jwks = HashMap::new();
        for issuer in &options.allowed_issuers {
            cached_jwks.insert(issuer.clone(), Arc::new(tokio::sync::RwLock::new(None)));
        }
        Self {
            options,
            cached_jwks,
        }
    }

    /// Fetches and caches JWKS for all allowed issuers.
    ///
    /// Must be called at least once before calling `validate`,
    /// and should be called periodically to refresh keys.
    pub async fn update_jwks(&self) -> Result<()> {
        // TODO: Instead of making caller deal with this, call this internally on startup and also
        // periodically on user request? This isn't latency sensitive after all, its fine if we sometimes
        // do extra work in `validate` and it makes the api simpler / harder to misuse.
        for (issuer, jwks_lock) in &self.cached_jwks {
            let openid_config_url = format!("{}/.well-known/openid-configuration", issuer);
            let jwks = jwks::Jwks::from_oidc_url(openid_config_url).await?;
            // Swap and keep the old value. Don't hold the lock for the logging afterwards.
            let old_jwks = {
                let mut jwks_guard = jwks_lock.write().await;
                jwks_guard.replace(jwks.clone())
            };
            // Log if this is the first time we fetched this issuer's JWKS,
            // or if the keys have changed since last time.
            match old_jwks {
                None => tracing::info!(
                    "Fetched JWKS for issuer {}. Key IDs: {:?}",
                    issuer,
                    jwks.keys.keys().collect::<Vec<_>>()
                ),
                Some(old) if jwks_differ(&old, &jwks) => tracing::info!(
                    "Updated JWKS for issuer {}. Key IDs: {:?}",
                    issuer,
                    jwks.keys.keys().collect::<Vec<_>>()
                ),
                _ => {} // Unchanged.
            }
        }
        Ok(())
    }

    /// Validates provided JWT token against configured audience, allowed issuers
    /// and using cached JWKS for signature validation.
    pub async fn validate(&self, token: &str) -> Result<Claims> {
        let unvalidated_issuer = get_unvalidated_issuer(token)?;
        let jwks_lock = self
            .cached_jwks
            .get(&unvalidated_issuer)
            .ok_or(Error::IssuerNotAllowed(unvalidated_issuer.clone()))?;

        let header = jsonwebtoken::decode_header(token)?;
        let kid = header.kid.as_ref().ok_or(Error::TokenMissingKid)?;

        let mut validation = jsonwebtoken::Validation::new(header.alg);
        // Validate expiry and not-before with some leeway.
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = self.options.token_age_leeway_seconds as u64;
        // Validate issuer and audience are allowed.
        validation.set_issuer(&self.options.allowed_issuers);
        validation.set_audience(std::slice::from_ref(&self.options.expected_audience));

        // Only holding read lock for the duration of signature validation.
        let raw_token = {
            let jwks_guard = jwks_lock.read().await;
            let key = jwks_guard
                .as_ref()
                .and_then(|jwks| jwks.keys.get(kid))
                .ok_or(Error::SigningKeyNotFound(kid.clone()))?;
            match jsonwebtoken::decode::<serde_json::Value>(token, &key.decoding_key, &validation) {
                Ok(token_data) => token_data,
                Err(e) => return Err(Error::InvalidJwt(e)),
            }
        };
        Claims::from_raw_claims(&raw_token.claims)
    }
}

/// Extracts the issuer claim from the token without validating the signature.
///
/// This is not used for security purposes, only to determine which JWKS to use for validation.
/// If the token has spoofed issuer it will not pass the actual validation step.
fn get_unvalidated_issuer(token: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct UnvalidatedIssuerClaim {
        iss: String,
    }
    // SAFETY: See function docstring, the issuer is not trusted here.
    let unvalidated_claims =
        jsonwebtoken::dangerous::insecure_decode::<UnvalidatedIssuerClaim>(token)?;
    Ok(unvalidated_claims.claims.iss)
}

fn jwks_differ(old: &jwks::Jwks, new: &jwks::Jwks) -> bool {
    // Compare the set of key ids only. The jwks crate does not implement Eq and hides the key material,
    // even though in this context it's not sensitive (public keys only). Unlikely the provider will
    // change key content without changing the kid, so this is good enough.
    let old_kids: std::collections::HashSet<_> = old.keys.keys().collect();
    let new_kids: std::collections::HashSet<_> = new.keys.keys().collect();
    old_kids != new_kids
}
