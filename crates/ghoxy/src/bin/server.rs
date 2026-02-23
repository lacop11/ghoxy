//! GHOXY server.

use std::net::SocketAddr;

use clap::Parser;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(version, about)]
// TODO: Doc comments for all flags, suitable defaults (or lack of + required to be explicit).
// TODO: Reorganize / rename flags for better UX. Should have common prefix for related stuff etc.
pub struct Args {
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

    let args = Args::parse();

    let options = ghoxy::server::ServerOptions {
        address: args.address,
        ruleset_dir: args.ruleset_dir,
        expected_audience: args.expected_audience,
        allowed_issuers: args.allowed_issuers,
        token_age_leeway_seconds: args.token_age_leeway_seconds,
        app_client_id: args.app_client_id,
        app_installation_id: args.app_installation_id,
        app_private_key_kms_path: args.app_private_key_kms_path,
        github_base_url: args.github_base_url,
        gcp_kms_api_base_url: args.gcp_kms_api_base_url,
        issuer_jwks_refresh_interval_seconds: args.issuer_jwks_refresh_interval_seconds,
    };

    let server = ghoxy::server::create_server(options).await.unwrap();
    server.await.unwrap();
}
