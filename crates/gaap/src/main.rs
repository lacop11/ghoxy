#[tokio::main]
async fn main() {
    let key = gcp_kms_sign::GcpKmsKeyVersion::new("projects/example-project/locations/global/keyRings/example-keyring/cryptoKeys/example-key/cryptoKeyVersions/1").await.unwrap();
    let data = b"hello world";
    let signature = key.asymmetric_sign(data).await.unwrap();
    println!("Signature: {:?}", signature);
}
