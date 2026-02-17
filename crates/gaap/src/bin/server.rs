//! GAAP server.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use clap::Parser;
use gaap::proxy::Proxy;
use std::{net::SocketAddr, sync::Arc};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    // TODO: Doc comments for all flags, suitable defaults (or lack of + required to be explicit).
    #[arg(long, default_value = "127.0.0.1:3000")]
    address: SocketAddr,

    #[arg(long, required = true)]
    ruleset_dir: std::path::PathBuf,

    #[arg(long, required = true)]
    expected_audience: String,
    #[arg(
        long,
        use_value_delimiter = true,
        default_value = "https://accounts.google.com,https://token.actions.githubusercontent.com"
    )]
    allowed_issuers: Vec<String>,
    #[arg(long, default_value_t = 60)]
    token_age_leeway_seconds: u32,

    #[arg(long)]
    app_client_id: String,
    #[arg(long)]
    app_installation_id: String,
    #[arg(long)]
    app_private_key_kms_path: String,

    #[arg(long, default_value = "https://api.github.com")]
    github_base_url: String,
}

#[tokio::main]
async fn main() {
    // TODO: Remove ring from all transitive deps and let it use aws-lc-rs by default automatically?
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

    let args = Args::parse();

    let client_token_validator =
        client_auth::TokenValidator::from_options(client_auth::TokenValidatorOptions {
            expected_audience: args.expected_audience,
            allowed_issuers: args.allowed_issuers,
            token_age_leeway_seconds: args.token_age_leeway_seconds,
        });
    // FIXME: this needs to be done periodically, ideally automatically.
    client_token_validator
        .update_jwks()
        .await
        .expect("Failed to fetch JWKS");

    let github_token_provider =
        github_auth::GithubTokenProvider::from_options(github_auth::GithubTokenProviderOptions {
            app_client_id: args.app_client_id,
            app_installation_id: args.app_installation_id,
            app_private_key_kms_path: args.app_private_key_kms_path,
            user_agent: gaap::user_agent::USER_AGENT.to_string(),
        })
        .await
        .expect("Failed to create GithubTokenProvider");

    let proxy = Proxy::new(gaap::proxy::ProxyOptions {
        ruleset_dir: args.ruleset_dir,
        github_base_url: args.github_base_url,
        client_token_validator,
        github_token_provider,
    })
    .await
    .expect("Failed to initialize proxy");

    // TODO: add tracing + compression middleware?
    let app = axum::Router::new()
        .route("/health", axum::routing::get(health))
        .fallback(proxy_request)
        .with_state(Arc::new(proxy))
        // TODO: Better tracing (custom layer that logs the relevant bits with masked secrets?)
        .layer(tower_http::trace::TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(args.address).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> &'static str {
    "OK"
}

async fn proxy_request(
    State(proxy): State<Arc<Proxy>>,
    req: Request<Body>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    match proxy.handle_request(req).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            tracing::error!("Error handling request: {}", e);
            match e {
                // TODO: Better status codes and messages for known error types.
                // Do not leak internal error details in responses, we log the full error for debugging
                // but client should get a censored message in some cases.
                _ => Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Unexpected server error".to_string(),
                )),
            }
        }
    }
}
