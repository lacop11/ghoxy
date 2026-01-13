//! GCP KMS Signer
//!
//! Provides API to sign data using assymetric keys stored in Google Cloud KMS.
//! No other KMS operations are supported.


#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented)]
#![deny(missing_docs)]

use thiserror::Error;

/// GCP KMS key version.
pub struct GcpKmsKeyVersion {
    credentials: google_cloud_auth::credentials::AccessTokenCredentials,
    key_version_name: String,
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
    UnsupportedState(String)
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
    UnsupportedAlgorithm(String)
}

impl GcpKmsKeyVersion {
    /// Create a new GcpKmsKeyVersion instance.
    ///
    /// Will check if the provided key version can be used for signing.
    pub async fn new(key_version_name: &str) -> Result<Self> {
        // Create client with default credentials.
        let credentials = google_cloud_auth::credentials::Builder::default()
            .build_access_token_credentials()?;
        let key_version = Self {
            credentials,
            key_version_name: key_version_name.to_string(),
        };

        let metadata = key_version.get_medatadata().await?;
        if let KeyVersionState::UnsupportedState(s) = metadata.state {
            return Err(Error::UnsupportedState(s));
        }
        if let KeyVersionAlgorithm::UnsupportedAlgorithm(s) = metadata.algorithm {
            return Err(Error::UnsupportedAlgorithm(s));
        }
        Ok(key_version)
    }

    /// Get metadata about the key version.
    pub async fn get_medatadata(&self) -> Result<KeyVersionMetadata> {
        let client = reqwest::Client::new();
        let token = self.credentials.access_token().await?;

        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}",
            self.key_version_name
        );

        let resp = client
            .get(&url)
            .bearer_auth(&token.token)
            .send()
            .await
            ?;

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
    pub async fn assymetric_sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        use base64::prelude::*;

        let client = reqwest::Client::new();
        let token = self.credentials.access_token().await?;

        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}:asymmetricSign",
            self.key_version_name
        );

        #[derive(serde::Serialize)]
        struct AsymmetricSignRequest {
            data: String,
        }

        #[derive(serde::Deserialize)]
        struct AsymmetricSignResponse {
            signature: String,
        }

        let request_body = AsymmetricSignRequest { data: BASE64_STANDARD.encode(data) };

        let resp = client
            .post(&url)
            .bearer_auth(&token.token)
            .json(&request_body)
            .send()
            .await
            ?;

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
    #[error("GCP Auth build error: {0}")]
    GcpAuthBuildError(#[from] google_cloud_auth::build_errors::Error),
    #[error("GCP Auth token error: {0}")]
    GcpAuthTokenError(#[from] google_cloud_auth::errors::CredentialsError),

    #[error("HTTP request error: {0}")]
    HttpRequestError(#[from] reqwest::Error),
    #[error("GCP API error: {0}")]
    GcpApiError(String),

    #[error("Key is in unsupported state: {0}")]
    UnsupportedState(String),
    #[error("Key has unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),
}

/// Result type for GcpKmsSign operations.
pub type Result<T> = std::result::Result<T, Error>;

// // todo : remove tokio dependency from this lib, tests can be mocked maybe? or just skip test here...
// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn it_works() {
//         let key = GcpKmsKeyVersion::new("projects/example-project/locations/global/keyRings/example-keyring/cryptoKeys/example-key/cryptoKeyVersions/1").await.unwrap();
//         let data = b"hello world";
//         let signature = key.assymetric_sign(data).await.unwrap();
//         println!("Signature: {:?}", signature);
//     }
// }
