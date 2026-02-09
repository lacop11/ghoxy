use crate::Result;
use serde::Deserialize;

#[derive(Debug)]
pub struct Rule {
    claims: cel::Program,
    rest: Vec<RuleRest>,
    // TODO: graphql allow rules.
}

#[derive(Debug)]
pub struct RuleRest {
    // TODO enumset?
    methods: Vec<ApiMethod>,
    // TODO: parsed segmented representation
    paths: Vec<String>,
    permissions: github_auth::Permissions,
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
        let rule_file: internal::Rule = toml::from_str(&content)?;

        Ok(Rule {
            claims: cel::Program::compile(&rule_file.claims)?,
            rest: rule_file
                .rest
                .into_iter()
                .map(RuleRest::from_rule_file_rest)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

impl RuleRest {
    fn from_rule_file_rest(rest: internal::RuleRest) -> Result<Self> {
        Ok(RuleRest {
            methods: rest.methods,
            // TODO: Validate the paths, maybe pre-compile into some mathing form (eg. Vec<Enum(Literal/Wildcard)> for each segment)
            // TODO: validate no overlap / ambiguity / duplicatio? can we do reliably at this point, or only
            // at rule evaluation time? (no early exit, check all and fail if multiple match)
            paths: rest.routes,
            permissions: github_auth::Permissions::from_permission_list(&rest.permissions)?,
        })
    }
}
// Raw format for deserializing the rule files, requires more validation
// and transforms into the public Rule struct.
mod internal {
use serde::Deserialize;
use super::ApiMethod;

#[derive(Debug, Deserialize)]
pub(crate) struct Rule {
    pub claims: String,
    pub rest: Vec<RuleRest>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RuleRest {
    pub methods: Vec<ApiMethod>,
    pub routes: Vec<String>,
    pub permissions: Vec<String>,
}

}
