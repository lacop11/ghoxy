#![allow(missing_docs)]

use aws_lc_rs::signature::KeyPair;
use base64::{Engine, prelude::*};
// Integration tests mocking all external dependencies (Github, OIDC issuer and GCP KMS).
use httpmock::prelude::*;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// TODO: Extract the mock and setup bits into shared library and make the actual tests simpler.
#[tokio::test]
async fn test_end_to_end() {
    // TODO remove if we can
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Need default crypto provider");

    // TODO move to some shared lib
    tracing_subscriber::registry()
        .with(
            // Allow overriding log levels with RUST_LOG. Some sensible defaults.
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,httpmock=debug")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mock_issuer = MockServer::start_async().await;
    dbg!("Mock issuer listening on {}", mock_issuer.address());

    // generate JWK/JWT, this is huge mess, clean up
    // generate rsa key pair
    let private_key =
        aws_lc_rs::signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let public_key = private_key.public_key();
    let jwks = serde_json::json!({
        "keys": [{
            "kid": "test-key-id",
            "alg": "RS256",
            "kty": "RSA",
            "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.modulus().big_endian_without_leading_zero()),
            "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.exponent().big_endian_without_leading_zero()),
        }]
    });
    //dbg!(jwks);
    // println!("{}", serde_json::to_string_pretty(&jwks).unwrap());
    // sign some test token
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test-key-id".to_string());
    #[derive(serde::Serialize)]
    struct Claims {
        iss: String,
        aud: String,
        exp: usize,
    }
    let claims = Claims {
        iss: format!("http://{}", mock_issuer.address()),
        aud: "test-audience".to_string(),
        exp: (std::time::SystemTime::now() + std::time::Duration::from_secs(300))
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize,
    };
    let partial_jwt = format!(
        "{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap()),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap()),
    );
    let mut signature = vec![0; private_key.public_modulus_len()];
    let rng = aws_lc_rs::rand::SystemRandom::new();
    private_key
        .sign(
            &aws_lc_rs::signature::RSA_PKCS1_SHA256,
            &rng,
            partial_jwt.as_bytes(),
            &mut signature,
        )
        .unwrap();
    let signed_jwt = format!(
        "{}.{}",
        partial_jwt,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    );
    // dbg!(signed_jwt);
    // end of garbage, clean up above^^

    let mock_issuer_openid = mock_issuer
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
    let mock_issuer_jwks = mock_issuer
        .mock_async(|when, then| {
            when.path("/jwks").method("GET");
            then.status(200)
                .header("content-type", "application/json")
                .body(serde_json::to_string(&jwks).unwrap());
        })
        .await;

    let mock_gcp_kms = MockServer::start_async().await;
    dbg!("Mock GCP KMS listening on {}", mock_gcp_kms.address());
    let mock_gcp_kms_keyinfo = mock_gcp_kms.mock_async(|when, then| {
        when.path("/v1/projects/example-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1").method("GET");
        then.status(200)
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "foo",
                "state": "ENABLED",
                "algorithm": "RSA_SIGN_PKCS1_2048_SHA256",
                "protectionLevel": "HSM",
            })
            .to_string(),
        );
    }).await;
    let dummy_signature = [42u8; 256]; // 2048 bit RSA signature.
    let mock_gcp_kms_sign = mock_gcp_kms.mock_async(|when, then| {
        when.path("/v1/projects/example-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1:asymmetricSign").method("POST");
        then.status(200)
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "signature": BASE64_STANDARD.encode(dummy_signature),
            })
            .to_string(),
        );
    }).await;

    let app_private_key = gcp_kms_sign::GcpKmsKeyVersion::new_for_test(
        "projects/example-project/locations/global/keyRings/test-ring/cryptoKeys/test-key/cryptoKeyVersions/1",
        Box::new(MockTokenProvider),
        format!("http://{}", mock_gcp_kms.address())
    ).await.unwrap();

    let mock_github = MockServer::start_async().await;
    let mock_github_installation_token = mock_github
        .mock_async(|when, then| {
            when.path("/app/installations/123456/access_tokens")
                .method("POST");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                serde_json::json!({
                    "token": "mock-installation-token",
                    "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                })
                .to_string(),
            );
        })
        .await;
    let mock_github_members = mock_github
        .mock_async(|when, then| {
            when.path("/orgs/someorg/members")
                .method("GET")
                .header("authorization", "Bearer mock-installation-token");
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    serde_json::json!([
                        {"login": "user1"},
                        {"login": "user2"},
                    ])
                    .to_string(),
                );
        })
        .await;

    let options = ghoxy::ServerOptions {
        address: std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::LOCALHOST,
            0,
        )),

        allowed_issuers: vec![format!("http://{}", mock_issuer.address())],
        expected_audience: "test-audience".to_string(),

        app_client_id: "test-client-id".to_string(),
        app_installation_id: "123456".to_string(),
        app_private_key,

        token_age_leeway_seconds: 60,
        issuer_jwks_refresh_interval_seconds: 3600,

        // TODO: generate temp dir with some rules for this
        ruleset_dir: std::path::PathBuf::from("../../example-rules"),

        github_base_url: format!("http://{}", mock_github.address()),
    };

    let server = ghoxy::create_server(options).await.unwrap();
    let address = server.local_addr().unwrap();
    dbg!("Server is listening on {:?}", address);

    // At this point the first-time initialization should be done.
    mock_issuer_openid.assert();
    mock_issuer_jwks.assert();
    mock_gcp_kms_keyinfo.assert();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_signal = async {
        shutdown_rx.await.ok();
    };
    let server = server.with_graceful_shutdown(shutdown_signal);

    // Start the server in background task.
    let server_task = tokio::spawn(async move {
        server.await.unwrap();
    });

    // Send request with our signed JWT.
    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/get-users/api/v3/orgs/someorg/members",
            address
        ))
        .bearer_auth(signed_jwt)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());

    mock_gcp_kms_sign.assert();
    mock_github_installation_token.assert();
    mock_github_members.assert();

    assert!(
        response.json::<serde_json::Value>().await.unwrap()
            == serde_json::json!([
                {"login": "user1"},
                {"login": "user2"},
            ])
    );

    // TODO: More test coverage:
    // - validate the headers in mocks (at least partially)
    // - incorrect JWT - rejected
    // - caches installation tokens
    // - proxies body in request too

    // Shutdown the server and wait for it to finish cleanly.
    shutdown_tx.send(()).unwrap();
    server_task.await.unwrap();
}

// TODO: Move to shared test module.
struct MockTokenProvider;

#[async_trait::async_trait]
impl gcp_kms_sign::TokenProvider for MockTokenProvider {
    async fn token(&self, _scopes: &[&str]) -> gcp_kms_sign::Result<token::Token> {
        Ok(token::Token::new("mock-token".to_string()))
    }
}
