//! GAAP server.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    // todo
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
}
