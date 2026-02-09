//! GAAP server.

use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:3000")]
    address: SocketAddr,
}

#[tokio::main]
async fn main() {
    // TODO
    // tracing_subscriber::fmt::init();

    let args = Args::parse();

    let app = axum::Router::new().route("/health", axum::routing::get(health));
    let listener = tokio::net::TcpListener::bind(args.address).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> &'static str {
    "OK"
}
