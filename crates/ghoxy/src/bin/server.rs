//! GHOXY server.

use clap::Parser;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
    info!("Initializing GHOXY server...");

    let args = ghoxy::server::Args::parse();

    let server = ghoxy::server::create_server(args).await.unwrap();
    server.await.unwrap();
}
