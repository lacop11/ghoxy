use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::test]
async fn test_end_to_end() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Need default crypto provider");

    // TODO: request tracing? how to attach unique traceid to all logs for a given request?
    tracing_subscriber::registry()
        .with(
            // Allow overriding log levels with RUST_LOG. Some sensible defaults.
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = ghoxy::server::Args {
        address: std::net::SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0)),

        // allowed_issuers: vec!["http://allowed-issuer.example.com".to_string()],
        allowed_issuers: vec!["https://accounts.google.com".to_string()],
        expected_audience: "test-audience".to_string(),

        app_client_id: "test-client-id".to_string(),
        app_installation_id: "test-installation-id".to_string(),
        // app_private_key_kms_path: "test-kms-path".to_string(),
        app_private_key_kms_path: "projects/example-project/locations/global/keyRings/example-keyring/cryptoKeys/example-key/cryptoKeyVersions/1".to_string(),

        token_age_leeway_seconds: 60,
        issuer_jwks_refresh_interval_seconds: 30,

        github_base_url: "http://github-base.example.com".to_string(),
        ruleset_dir: std::path::PathBuf::from("../../example-rules"),
    };

    let server = ghoxy::server::create_server(args).await.unwrap();
    let address = server.local_addr();

    dbg!("Server is listening on {:?}", address);

    // TODO graceful shutdown
    server.await.unwrap();
}
