//! Rule parsing and evaluation.

mod error;
pub use error::{Error, Result};

mod rule;
pub use rule::{RestMethod, Rule, RuleRest};

mod ruleset;
pub use ruleset::RuleSet;
