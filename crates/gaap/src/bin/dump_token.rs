/// Testing tool to validate and dump parsed JWT tokens.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// The expected audience for provided tokens.
    #[arg(long, default_value = "https://gaap.example.com")]
    expected_audience: String,

    /// Comma-separated list of allowed issuers.
    #[arg(
        long,
        use_value_delimiter = true,
        default_value = "https://accounts.google.com,https://token.actions.githubusercontent.com"
    )]
    allowed_issuers: Vec<String>,

    /// Leeway in seconds to allow for clock skew when validating token age.
    #[arg(long, default_value_t = 60)]
    token_age_leeway_seconds: u32,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let token = match std::io::read_to_string(std::io::stdin()) {
        Ok(t) => t.trim().to_string(),
        Err(e) => {
            eprintln!("Must provide token to stdin: {}", e);
            std::process::exit(1);
        }
    };

    let validator = client_auth::TokenValidator::from_options(client_auth::TokenValidatorOptions {
        expected_audience: args.expected_audience,
        allowed_issuers: dbg!(args.allowed_issuers),
        token_age_leeway_seconds: args.token_age_leeway_seconds,
    });

    if let Err(e) = validator.update_jwks().await {
        eprintln!("Failed to fetch JWKS: {}", e);
        std::process::exit(1);
    }

    match validator.validate(&token).await {
        Ok(claims) => {
            println!("Token is valid. Claims: {:#?}", claims);
        }
        Err(e) => {
            eprintln!("Token is invalid: {}", e);
            std::process::exit(1);
        }
    }
}
