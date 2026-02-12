//! GAAP server.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use clap::Parser;
use gaap::proxy::Proxy;
use std::{net::SocketAddr, sync::Arc};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:3000")]
    address: SocketAddr,

    #[arg(long, required = true)]
    ruleset_dir: std::path::PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args = Args::parse();

    let proxy = Proxy::new(gaap::proxy::ProxyOptions {
        ruleset_dir: args.ruleset_dir,
    }).await.expect("Failed to initialize proxy");

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
