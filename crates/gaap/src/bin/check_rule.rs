//! Testing tool to validate rule file and potentially evaluate for some request.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Path to the rule file to validate.
    #[arg(long)]
    rule_file: String,
}

fn main() {
    let args = Args::parse();
    let rule = match rules::Rule::from_file(&args.rule_file) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to parse rule file: {}", e);
            std::process::exit(1);
        }
    };
    dbg!("Successfully parsed rule file: {:#?}", rule);
}
