//! GCP KMS Signer
//!
//! Provides API to sign data using asymmetric keys stored in Google Cloud KMS.
//! No other KMS operations are supported.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]
#![deny(missing_docs)]

mod auth;
pub use auth::{TokenProvider};

use thiserror::Error;

/// GCP KMS key version.
pub struct GcpKmsKeyVersion {
    key_version_name: String,
    auth_provider: Box<dyn TokenProvider + Send + Sync>,
    gcp_kms_api_base_url: String,
}

/// Metadata about a KMS key version.
///
/// Only a subset of the fields and values are supported.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct KeyVersionMetadata {
    /// The resource name of the key version.
    pub name: String,
    /// The state of the key version.
    pub state: KeyVersionState,
    /// The algorithm of the key version.
    pub algorithm: KeyVersionAlgorithm,
    /// The protection level of the key version.
    #[serde(rename = "protectionLevel")]
    pub protection_level: KeyVersionProtectionLevel,
}

/// The state of a KMS key version.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum KeyVersionState {
    /// The key version is enabled.
    /// This is the only supported state.
    #[serde(rename = "ENABLED")]
    Enabled,
    /// Unsupported state.
    /// We don't care what the state is, the key version can't be used to sign.
    #[serde(untagged)]
    UnsupportedState(String),
}

/// The algorithm of a KMS key version.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum KeyVersionAlgorithm {
    /// RSA_SIGN_PKCS1_2048_SHA256
    #[serde(rename = "RSA_SIGN_PKCS1_2048_SHA256")]
    RsaSign2048Pkcs1Sha256,
    // TODO: This is not exhaustive list, we should add more supported algorithms as needed,
    //       or maybe just allow anything starting with RSA_SIGN_... ?
    /// Unsupported algorithm.
    /// We don't care what the algorithm is, the key version can't be used to sign.
    #[serde(untagged)]
    UnsupportedAlgorithm(String),
}

/// The protection level of a KMS key version.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum KeyVersionProtectionLevel {
    /// The key is stored in HSM.
    /// This is the only supported protection level.
    #[serde(rename = "HSM")]
    Hsm,
    /// Unsupported protection level.
    /// We don't care what the protection level is, to ensure best possible security we
    /// refuse anything other than HSM even if it would technically work.
    #[serde(untagged)]
    UnsupportedProtectionLevel(String),
}

const SCOPES: &[&str] = &["https://www.googleapis.com/auth/cloudkms"];

impl GcpKmsKeyVersion {
    /// Create a new GcpKmsKeyVersion instance.
    ///
    /// Will check if the provided key version can be used for signing.
    pub async fn new(key_version_name: &str) -> Result<Self> {
        let key_version = Self {
            key_version_name: key_version_name.to_string(),
            auth_provider: Box::new(auth::RealTokenProvider::new().await?),
            gcp_kms_api_base_url:"https://cloudkms.googleapis.com".to_string(),
        };
        key_version.validate_key().await?;
        Ok(key_version)
    }

    /// Create a new GcpKmsKeyVersion instance for testing.
    ///
    /// Can override the auth provider and KMS API base url to allow mocking the GCP endpoints.
    pub async fn new_for_test(key_version_name: &str, auth_provider: Box<dyn TokenProvider + Send + Sync>, gcp_kms_api_base_url: &str) -> Result<Self> {
        let key_version = Self {
            key_version_name: key_version_name.to_string(),
            auth_provider,
            gcp_kms_api_base_url: gcp_kms_api_base_url.to_string(),
        };
        key_version.validate_key().await?;
        Ok(key_version)
    }

    async fn validate_key(&self) -> Result<()> {
        let metadata = self.get_medatadata().await?;
        if let KeyVersionState::UnsupportedState(s) = metadata.state {
            return Err(Error::UnsupportedState(s));
        }
        if let KeyVersionAlgorithm::UnsupportedAlgorithm(s) = metadata.algorithm {
            return Err(Error::UnsupportedAlgorithm(s));
        }
        if let KeyVersionProtectionLevel::UnsupportedProtectionLevel(s) = metadata.protection_level
        {
            return Err(Error::UnsupportedProtectionLevel(s));
        }
        Ok(())
    }

    /// Get metadata about the key version.
    pub async fn get_medatadata(&self) -> Result<KeyVersionMetadata> {
        let client = reqwest::Client::new();
        let token = self.auth_provider.token(SCOPES).await?;

        let url = format!("{}/v1/{}", self.gcp_kms_api_base_url, self.key_version_name);

        let resp = client.get(&url).bearer_auth(token.get_sensitive_value()).send().await?;

        if resp.status().is_success() {
            let meta: KeyVersionMetadata = resp.json().await?;
            Ok(meta)
        } else {
            Err(Error::GcpApiError(resp.text().await?))
        }
    }

    /// Sign data using the key version.
    ///
    /// This takes care of base64 encoding/decoding as needed by GCP KMS API, the input and output are raw bytes.
    pub async fn asymmetric_sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        use base64::prelude::*;

        let client = reqwest::Client::new();
        let token = self.auth_provider.token(SCOPES).await?;

        let url = format!(
            "{}/v1/{}:asymmetricSign",
            self.gcp_kms_api_base_url, self.key_version_name
        );

        #[derive(serde::Serialize)]
        struct AsymmetricSignRequest {
            data: String,
        }

        #[derive(serde::Deserialize)]
        struct AsymmetricSignResponse {
            signature: String,
        }

        let request_body = AsymmetricSignRequest {
            data: BASE64_STANDARD.encode(data),
        };

        let resp = client
            .post(&url)
            .bearer_auth(token.get_sensitive_value())
            .json(&request_body)
            .send()
            .await?;

        if resp.status().is_success() {
            let sign_resp: AsymmetricSignResponse = resp.json().await?;
            let signature = BASE64_STANDARD.decode(sign_resp.signature)?;
            Ok(signature)
        } else {
            Err(Error::GcpApiError(resp.text().await?))
        }
    }
}

/// Errors for GcpKmsSign operations.
#[derive(Error, Debug)]
#[allow(missing_docs)]
pub enum Error {
    #[error("GCP Auth error: {0}")]
    GcpAuthError(#[from] gcp_auth::Error),

    #[error("HTTP request error: {0}")]
    HttpRequestError(#[from] reqwest::Error),
    #[error("GCP API error: {0}")]
    GcpApiError(String),

    #[error("Key is in unsupported state: {0}")]
    UnsupportedState(String),
    #[error("Key has unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Key has unsupported protection level: {0}")]
    UnsupportedProtectionLevel(String),

    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
}

/// Result type for GcpKmsSign operations.
pub type Result<T> = std::result::Result<T, Error>;

// TODO: Maybe add a unit test, but the logic is pretty simple if we mock out the GCP endpoints...
