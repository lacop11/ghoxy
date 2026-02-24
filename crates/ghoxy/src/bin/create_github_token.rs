//! Testing tool to use the KMS private key to create Github access token.

use clap::Parser;
use gcp_kms_sign::GcpKmsKeyVersion;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// The GitHub App client id.
    #[arg(long)]
    app_client_id: String,

    /// The GitHub App installation id.
    #[arg(long)]
    app_installation_id: String,

    /// Path to the GitHub App private key on GCP KMS.
    #[arg(long)]
    app_private_key_kms_path: String,

    /// Comma-separated list of permissions to request, in the form <permission>:<access>,
    /// for example "issues:read,contents:write". Must not be empty, and must be a subset
    /// of the permissions granted to the app installation.
    #[arg(long, use_value_delimiter = true)]
    permissions: Vec<String>,
}

#[tokio::main]
async fn main() {
    // TODO: Remove ring from all transitive deps and let it use aws-lc-rs by default automatically?
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Need default crypto provider");

    let args = Args::parse();

    let permissions = github_auth::Permissions::from_permission_list(&args.permissions)
        .expect("Invalid permissions");
    let github_token_provider =
        github_auth::GithubTokenProvider::from_options(github_auth::GithubTokenProviderOptions {
            github_api_base_url: "https://api.github.com".to_string(),
            app_client_id: args.app_client_id,
            app_installation_id: args.app_installation_id,
            app_key_kms: GcpKmsKeyVersion::new(&args.app_private_key_kms_path)
                .await
                .expect("Failed to create GcpKmsKeyVersion"),
            user_agent: ghoxy::USER_AGENT.to_string(),
        })
        .await
        .expect("Failed to create GithubTokenProvider");

    let token = github_token_provider
        .get_installation_access_token(&permissions)
        .await
        .expect("Failed to get Github installation access token");

    println!("Github installation token: {}", token);
}
