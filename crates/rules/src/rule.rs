use crate::Result;
use serde::Deserialize;

#[derive(Debug)]
pub struct Rule {
    claims: cel::Program,
    allow: Vec<RuleAllow>,
}

#[derive(Debug)]
pub struct RuleAllow {
    permissions: github_auth::Permissions,
    rest: Vec<RuleAllowRest>,
    // TODO: graphql allow rules.
}

#[derive(Debug)]
pub struct RuleAllowRest {
    method: ApiMethod,
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ApiMethod {
    // TODO: More methods as needed.
    Get,
    Post,
}

impl Rule {
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let rule_file: internal::RuleFile = toml::from_str(&content)?;

        Ok(Rule {
            claims: cel::Program::compile(&rule_file.claims)?,
            allow: rule_file
                .allow
                .into_iter()
                .map(RuleAllow::from_rule_file_allow)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

impl RuleAllow {
    fn from_rule_file_allow(allow: internal::RuleFileAllow) -> Result<Self> {
        Ok(RuleAllow {
            permissions: github_auth::Permissions::from_permission_list(&allow.permissions)?,
            rest: allow
                .rest
                .into_iter()
                .map(RuleAllowRest::from_rule_file_allow_rest)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

impl RuleAllowRest {
    fn from_rule_file_allow_rest(allow_rest: internal::RuleFileAllowRest) -> Result<Self> {
        // TODO: Validate the path, maybe pre-compile into some mathing form (eg. Vec<Enum(Literal/Wildcard)> for each segment)
        Ok(RuleAllowRest {
            method: allow_rest.method,
            path: allow_rest.path,
        })
    }
}

// Raw format for deserializing the rule files, requires more validation
// and transforms into the public Rule struct.
mod internal {
use serde::Deserialize;
use super::ApiMethod;

#[derive(Debug, Deserialize)]
pub(crate) struct RuleFile {
    pub claims: String,
    pub allow: Vec<RuleFileAllow>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RuleFileAllow {
    pub permissions: Vec<String>,
    pub rest: Vec<RuleFileAllowRest>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RuleFileAllowRest {
    pub method: ApiMethod,
    pub path: String,
}

}
