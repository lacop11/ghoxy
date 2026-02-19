use httpmock::prelude::*;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

// TODO: Extract the mock and setup bits into shared library and make the actual tests simpler.
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

    let mock_issuer = MockServer::start_async().await;
    dbg!("Mock issuer listening on {}", mock_issuer.address());

    mock_issuer
        .mock_async(|when, then| {
            when.path("/.well-known/openid-configuration").method("GET");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    serde_json::json!({
                        "jwks_uri": format!("http://{}/jwks", mock_issuer.address())
                    })
                    .to_string(),
                );
        })
        .await;
    mock_issuer
        .mock_async(|when, then| {
            when.path("/jwks").method("GET");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    serde_json::json!({
                        "keys": []
                    })
                    .to_string(),
                );
        })
        .await;

    let args = ghoxy::server::Args {
        address: std::net::SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0)),

        allowed_issuers: vec![format!("http://{}", mock_issuer.address())],
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
