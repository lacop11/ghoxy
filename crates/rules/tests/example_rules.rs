// Test that all the example rules are actually valid.

#![allow(missing_docs)]

use rules::RuleSet;

#[test]
fn test_example_rules() {
    let example_rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("example-rules");
    _ = RuleSet::from_directory(example_rules_dir).unwrap();
}
