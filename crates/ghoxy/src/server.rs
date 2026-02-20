use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::IntoResponse,
};
use clap::Parser;
use gcp_kms_sign::GcpKmsKeyVersion;
use tracing::info;

use crate::{error::ServerResult, proxy::Proxy};

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    // TODO: Doc comments for all flags, suitable defaults (or lack of + required to be explicit).
    #[arg(long, default_value = "127.0.0.1:3000")]
    pub address: SocketAddr,

    #[arg(long, required = true)]
    pub ruleset_dir: std::path::PathBuf,

    #[arg(long, required = true)]
    pub expected_audience: String,
    #[arg(
        long,
        use_value_delimiter = true,
        default_value = "https://accounts.google.com,https://token.actions.githubusercontent.com"
    )]
    pub allowed_issuers: Vec<String>,
    #[arg(long, default_value_t = 60)]
    pub token_age_leeway_seconds: u32,

    #[arg(long)]
    pub app_client_id: String,
    #[arg(long)]
    pub app_installation_id: String,
    #[arg(long)]
    pub app_private_key_kms_path: String,

    #[arg(long, default_value = "https://api.github.com")]
    pub github_base_url: String,
    #[arg(long)]
    pub gcp_kms_api_base_url: Option<String>,

    #[arg(long, default_value_t = 30)]
    pub issuer_jwks_refresh_interval_seconds: u64,
}

async fn health() -> &'static str {
    "OK"
}

// To avoid leaking any internal details in the error response, we only allow
// returning static strings. Full error details are logged and legitimate internal
// users can find them.
async fn proxy_request(
    State(proxy): State<Arc<Proxy>>,
    req: Request<Body>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    match proxy.handle_request(req).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            // Log the full error for debugging, as warning only,
            // since this can be user's fault.
            tracing::warn!("Error handling request: {}", e);

            use crate::error::ProxyError::*;
            let code_and_message = match e {
                InvalidRequestPath => (StatusCode::NOT_FOUND, "Invalid request path"),
                NoSuchRule(_) => (StatusCode::NOT_FOUND, "No such rule"),
                InvalidRules(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid rules configuration",
                ),
                TokenValidationError(_) => {
                    (StatusCode::UNAUTHORIZED, "Invalid authorization token")
                }
                MissingAuthorizationHeader => {
                    (StatusCode::UNAUTHORIZED, "Missing authorization header")
                }
                InvalidAuthorizationHeader => {
                    (StatusCode::UNAUTHORIZED, "Invalid authorization header")
                }
                UnsupportedHttpMethod(_) => {
                    (StatusCode::METHOD_NOT_ALLOWED, "Unsupported HTTP method")
                }
                UnsupportedGraphqlMethod => {
                    (StatusCode::METHOD_NOT_ALLOWED, "Unsupported GraphQL method")
                }
                RequestNotAllowedByRule => (StatusCode::FORBIDDEN, "Request not allowed by rules"),
                GithubTokenProviderError(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Github token provider error",
                ),
                HttpClientError(_) => (StatusCode::BAD_GATEWAY, "Upstream service error"),
                HttpResponseError(_) => (StatusCode::BAD_GATEWAY, "Upstream service error"),
            };
            Err(code_and_message)
        }
    }
}

pub async fn create_server(
    args: Args,
) -> ServerResult<axum::serve::Serve<tokio::net::TcpListener, Router, Router>> {
    let client_token_validator =
        client_auth::TokenValidator::from_options(client_auth::TokenValidatorOptions {
            expected_audience: args.expected_audience,
            allowed_issuers: args.allowed_issuers,
            token_age_leeway_seconds: args.token_age_leeway_seconds,
        });
    // Run the initial refresh before starting the server so we can fail fast if something
    // is misconfigured, and can handle client requests right away.
    client_token_validator.update_jwks().await?;

    let github_token_provider =
        github_auth::GithubTokenProvider::from_options(github_auth::GithubTokenProviderOptions {
            github_api_base_url: args.github_base_url.clone(),
            app_client_id: args.app_client_id,
            app_installation_id: args.app_installation_id,
            app_key_kms: GcpKmsKeyVersion::new(
                &args.app_private_key_kms_path,
                args.gcp_kms_api_base_url.as_deref(),
            )
            .await?,
            user_agent: crate::user_agent::USER_AGENT.to_string(),
        })
        .await?;

    let proxy = Proxy::new(crate::proxy::ProxyOptions {
        ruleset_dir: args.ruleset_dir,
        github_base_url: args.github_base_url,
        client_token_validator,
        github_token_provider,
    })
    .await?;
    let proxy = Arc::new(proxy);

    // Start background task to periodically refresh JWKS to handle issuers rotating keys.
    let proxy_clone = proxy.clone();
    tokio::spawn(async move {
        proxy_clone
            .refresh_jwks_periodically(std::time::Duration::from_secs(
                args.issuer_jwks_refresh_interval_seconds,
            ))
            .await;
    });

    // TODO: add tracing + compression middleware?
    let app = axum::Router::new()
        .route("/health", axum::routing::get(health))
        .fallback(proxy_request)
        .with_state(proxy.clone())
        // TODO: Better tracing (custom layer that logs the relevant bits with masked secrets?)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    info!("Starting GHOXY server on {}", args.address);
    let listener = tokio::net::TcpListener::bind(args.address).await?;
    Ok(axum::serve(listener, app))
}
