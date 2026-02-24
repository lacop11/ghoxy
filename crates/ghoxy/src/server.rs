use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::IntoResponse,
};
use tracing::info;

use crate::{error::ServerResult, proxy::Proxy};

// TODO: Fix, add docs.
#[allow(missing_docs)]
pub struct ServerOptions {
    pub address: SocketAddr,

    pub ruleset_dir: std::path::PathBuf,

    pub expected_audience: String,
    pub allowed_issuers: Vec<String>,
    pub token_age_leeway_seconds: u32,

    pub app_client_id: String,
    pub app_installation_id: String,
    pub app_private_key: gcp_kms_sign::GcpKmsKeyVersion,

    pub github_base_url: String,

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

/// Create axum server with given options.
/// Caller must await it to run the server loop until shutdown.
pub async fn create_server(
    options: ServerOptions,
) -> ServerResult<axum::serve::Serve<tokio::net::TcpListener, Router, Router>> {
    let client_token_validator =
        client_auth::TokenValidator::from_options(client_auth::TokenValidatorOptions {
            expected_audience: options.expected_audience,
            allowed_issuers: options.allowed_issuers,
            token_age_leeway_seconds: options.token_age_leeway_seconds,
        });
    // Run the initial refresh before starting the server so we can fail fast if something
    // is misconfigured, and can handle client requests right away.
    client_token_validator.update_jwks().await?;

    let github_token_provider =
        github_auth::GithubTokenProvider::from_options(github_auth::GithubTokenProviderOptions {
            github_api_base_url: options.github_base_url.clone(),
            app_client_id: options.app_client_id,
            app_installation_id: options.app_installation_id,
            app_key_kms: options.app_private_key,
            user_agent: crate::user_agent::USER_AGENT.to_string(),
        })
        .await?;

    let proxy = Proxy::new(crate::proxy::ProxyOptions {
        ruleset_dir: options.ruleset_dir,
        github_base_url: options.github_base_url,
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
                options.issuer_jwks_refresh_interval_seconds,
            ))
            .await;
    });

    // TODO: Add tracing middleware for support of trace-id propagation from loadbalancer?
    let app = axum::Router::new()
        .route("/health", axum::routing::get(health))
        .fallback(proxy_request)
        .with_state(proxy.clone())
        // TODO: Better tracing (custom layer that logs the relevant bits with masked secrets?)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    info!("Starting GHOXY server on {}", options.address);
    let listener = tokio::net::TcpListener::bind(options.address).await?;
    Ok(axum::serve(listener, app))
}
