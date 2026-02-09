use crate::Result;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Deserialize, Eq, PartialEq)]
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

        // TODO: validate the cel rule:
        // - should reference some claims
        // - should pass for some example claims (doesn't matter if true/false but not crash)
        Ok(Rule {
            claims: cel::Program::compile(&rule_file.claims)?,
            rest: rule_file
                .rest
                .into_iter()
                .map(RuleRest::from_rule_file_rest)
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn check_claims(&self, claims: &client_auth::Claims) -> Result<bool> {
        let mut context = cel::Context::default();
        context.add_variable("claims", &claims.known)?;
        context.add_variable("raw_claims", &claims.raw_claims)?;
        match self.claims.execute(&context)? {
            cel::Value::Bool(b) => Ok(b),
            val => Err(crate::Error::InvalidCelValue(val)),
        }
    }

    /// Find matching rule for given request if it matches any.
    /// Returns the permissions that should be used for the request if it matches, or None if it doesn't match.
    pub fn check_rest_request(
        &self,
        claims: &client_auth::Claims,
        method: &ApiMethod,
        path: &str,
    ) -> Result<Option<github_auth::Permissions>> {
        if !self.check_claims(claims)? {
            // Request is not allowed.
            return Ok(None);
        }

        // Find matching rules. If there are multiple the rule is ambiguous and we should fail.
        let mut matching_rest_rule = None;
        for rest_rule in &self.rest {
            if !rest_rule.methods.contains(method) {
                continue;
            }
            // TODO: check the path match including wildcards
            if matching_rest_rule.is_some() {
                return Err(crate::Error::AmbiguousRule);
            }
            matching_rest_rule = Some(rest_rule);
        }
        Ok(matching_rest_rule.map(|r| r.permissions.clone()))
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
    use super::ApiMethod;
    use serde::Deserialize;

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
