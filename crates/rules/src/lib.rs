//! Rule parsing and evaluation.

mod error;
pub use error::{Error, Result};

mod rule;
pub use rule::{Rule, RuleRest};

mod ruleset;
pub use ruleset::RuleSet;
