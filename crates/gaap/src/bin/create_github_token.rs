//! Testing tool to use the KMS private key to create Github access token.

#[tokio::main]
async fn main() {
    // TODO: Remove ring from all transitive deps and let it use aws-lc-rs by default automatically?
    rustls::crypto::aws_lc_rs::default_provider().install_default().expect("Need default crypto provider");

    let key = gcp_kms_sign::GcpKmsKeyVersion::new("projects/example-project/locations/global/keyRings/example-keyring/cryptoKeys/example-key/cryptoKeyVersions/1").await.unwrap();
    let data = b"hello world";
    let signature = key.asymmetric_sign(data).await.unwrap();
    println!("Signature: {:?}", signature);
}
