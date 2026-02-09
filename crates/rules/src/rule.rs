use crate::Result;
use serde::Deserialize;

#[derive(Debug)]
pub struct Rule {

}

impl Rule {
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let rule_file: RuleFile = toml::from_str(&content)?;
        dbg!("Parsed rule file: {:#?}", rule_file);
        Ok(Rule {})
    }
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    claims: String,
    allow: Vec<RuleFileAllow>,
}

#[derive(Debug, Deserialize)]
struct RuleFileAllow {
    permissions: Vec<String>,
    rest: Vec<RuleFileAllowRest>,
}

#[derive(Debug, Deserialize)]
struct RuleFileAllowRest {
    method: ApiMethod,
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum ApiMethod {
    // TODO: More methods as needed.
    Get,
    Post,
}
