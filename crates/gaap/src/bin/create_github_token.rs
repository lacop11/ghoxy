//! Testing tool to use the KMS private key to create Github access token.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// The GitHub App client id.
    #[arg(long)]
    app_client_id: String,

    /// Path to the GitHub App private key on GCP KMS.
    #[arg(long)]
    app_private_key: String,

    /// Token lifetime in seconds (max 600s for GitHub).
    #[arg(long, default_value_t = 600)]
    token_lifetime_seconds: u32,
}


#[tokio::main]
async fn main() {
    // TODO: Remove ring from all transitive deps and let it use aws-lc-rs by default automatically?
    rustls::crypto::aws_lc_rs::default_provider().install_default().expect("Need default crypto provider");

    let args = Args::parse();

    // TODO
}
