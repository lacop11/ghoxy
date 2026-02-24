use regex::Regex;

use crate::Result;

/// A single rule with CEL program for checking claims and allowed REST or GraphQL requests.
#[derive(Debug)]
pub struct Rule {
    claims: cel::Program,
    rest: Vec<RuleRest>,
    // TODO: graphql allow rules.
}

/// A rule for REST API requests.
#[derive(Debug)]
pub struct RuleRest {
    // TODO enumset?
    methods: Vec<http::Method>,
    routes: Vec<Regex>,
    permissions: github_auth::Permissions,
}

impl Rule {
    /// Loads a rule from a file, parsing and validating it.
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Rule::from_str(&content)
    }

    fn from_str(content: &str) -> Result<Self> {
        let rule_file: internal::Rule = toml::from_str(content)?;

        // TODO: validate the cel rule:
        // - should reference some claims
        // - should pass for some example claims (doesn't matter if true/false but not crash)
        Ok(Rule {
            claims: cel::Program::compile(&rule_file.claims)?,
            rest: check_not_empty(
                rule_file
                    .rest
                    .into_iter()
                    .map(RuleRest::from_rule_file_rest)
                    .collect::<Result<Vec<_>>>()?,
                crate::Error::NoRulesSpecified,
            )?,
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
        method: &http::Method,
        path: &str,
    ) -> Result<Option<github_auth::Permissions>> {
        if !self.check_claims(claims)? {
            // Request is not allowed.
            return Ok(None);
        }

        // Find matching rule. Fail if multiple rules match.
        let mut matching_rest_rule = None;
        for rest_rule in &self.rest {
            if !rest_rule.methods.contains(method) {
                continue;
            }

            if !rest_rule.routes.iter().any(|r| r.is_match(path)) {
                continue;
            }

            // Match must be unambigious, otherwise it's not clear which permissions to use.
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
        let methods = rest
            .methods
            .iter()
            .map(AsRef::as_ref)
            .map(parse_method)
            .collect::<Result<Vec<_>>>()?;
        let routes = rest
            .routes
            .iter()
            // Force fully anchored regex.
            .map(anchored_regex)
            .collect::<Result<Vec<_>>>()?;
        Ok(RuleRest {
            methods: check_not_empty(methods, crate::Error::EmptyMethodList)?,
            routes: check_not_empty(routes, crate::Error::EmptyPathList)?,
            permissions: github_auth::Permissions::from_permission_list(&rest.permissions)?,
        })
    }
}

fn parse_method(method: &str) -> Result<http::Method> {
    use http::Method;
    let method = method.parse()?;
    match method {
        // Only some methods are allowed, we don't want to allow weird extensions.
        // https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api?apiVersion=2022-11-28#http-method
        Method::GET | Method::POST | Method::PUT | Method::DELETE | Method::PATCH => Ok(method),
        _ => Err(crate::Error::RestMethodNotAllowed(method)),
    }
}

fn anchored_regex(s: &String) -> Result<Regex> {
    if s.starts_with('^') || s.ends_with('$') {
        return Err(crate::Error::RegexExplicitlyAnchored);
    }
    Ok(Regex::new(&format!("^{}$", s))?)
}

// Raw format for deserializing the rule files, requires more validation
// and transforms into the public Rule struct.
mod internal {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub(crate) struct Rule {
        pub claims: String,
        #[serde(default)]
        pub rest: Vec<RuleRest>,
    }

    #[derive(Debug, Deserialize)]
    pub(crate) struct RuleRest {
        pub methods: Vec<String>,
        pub routes: Vec<String>,
        pub permissions: Vec<String>,
    }
}

fn check_not_empty<T>(list: Vec<T>, err: crate::Error) -> Result<Vec<T>> {
    if list.is_empty() {
        return Err(err);
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_rule() {
        let rule_str = r#"
            claims = "true"
            [[rest]]
            methods = ["GET"]
            routes = ["/foo"]
            permissions = ["repo:read"]
        "#;
        let rule = Rule::from_str(rule_str).unwrap();

        // Allowed.
        let claims = client_auth::Claims {
            known: None,
            raw_claims: serde_json::json!({}),
        };
        let permissions = rule
            .check_rest_request(&claims, &http::Method::GET, "/foo")
            .unwrap();
        assert_eq!(
            permissions,
            Some(
                github_auth::Permissions::from_permission_list(&["repo:read".to_string()]).unwrap()
            )
        );

        // Not allowed because of method.
        let permissions = rule
            .check_rest_request(&claims, &http::Method::POST, "/foo")
            .unwrap();
        assert_eq!(permissions, None);

        // Not allowed because of path.
        let permissions = rule
            .check_rest_request(&claims, &http::Method::GET, "/bar")
            .unwrap();
        assert_eq!(permissions, None);
    }

    #[test]
    fn test_bad_rule() {
        // Invalid CEL.
        let rule_str = r#"
            claims = "syntax error"
            [[rest]]
            methods = ["GET"]
            routes = ["/foo"]
            permissions = ["repo:read"]
        "#;
        assert!(Rule::from_str(rule_str).is_err());

        // No rules.
        let rule_str = r#"
            claims = "true"
        "#;
        assert!(Rule::from_str(rule_str).is_err());

        // No methods.
        let rule_str = r#"
            claims = "true"
            [[rest]]
            methods = []
            routes = ["/foo"]
            permissions = ["repo:read"]
        "#;
        assert!(Rule::from_str(rule_str).is_err());

        // No routes.
        let rule_str = r#"
            claims = "true"
            [[rest]]
            methods = ["GET"]
            routes = []
            permissions = ["repo:read"]
        "#;
        assert!(Rule::from_str(rule_str).is_err());

        // Bad regex.
        let rule_str = r#"
            claims = "true"
            [[rest]]
            methods = ["GET"]
            routes = ["/(unclosed/"]
            permissions = ["repo:read"]
        "#;
        assert!(Rule::from_str(rule_str).is_err());

        // Explicitly anchored regex.
        let rule_str = r#"
            claims = "true"
            [[rest]]
            methods = ["GET"]
            routes = ["^/foo$"]
            permissions = ["repo:read"]
        "#;
        assert!(Rule::from_str(rule_str).is_err());

        // No permissions.
        let rule_str = r#"
            claims = "true"
            [[rest]]
            methods = ["GET"]
            routes = ["/foo"]
            permissions = []
        "#;
        assert!(Rule::from_str(rule_str).is_err());
    }

    // TODO: This test would be more useful when we have some custom rules, not using regexes.
    #[test]
    fn test_route_matches() {
        let rule_str = r#"
            claims = "true"
            [[rest]]
            methods = ["GET"]
            routes = [
                "/foo",
                "/orgs/[^/]+/members",
                "/users/(alice|bob)/repos",
            ]
            permissions = ["repo:read"]
        "#;
        let rule = Rule::from_str(rule_str).unwrap();

        let claims = client_auth::Claims {
            known: None,
            raw_claims: serde_json::json!({}),
        };

        assert!(matches!(
            rule.check_rest_request(&claims, &http::Method::GET, "/foo"),
            Ok(Some(_))
        ));
        assert!(matches!(
            rule.check_rest_request(&claims, &http::Method::GET, "/foo/bar"),
            Ok(None)
        ));
        assert!(matches!(
            rule.check_rest_request(&claims, &http::Method::GET, "/orgs/arbitrary/members"),
            Ok(Some(_))
        ));
        assert!(matches!(
            rule.check_rest_request(
                &claims,
                &http::Method::GET,
                "/orgs/sneaky/extra/segments/members"
            ),
            Ok(None)
        ));
        assert!(matches!(
            rule.check_rest_request(&claims, &http::Method::GET, "/users/alice/repos"),
            Ok(Some(_))
        ));
        assert!(matches!(
            rule.check_rest_request(&claims, &http::Method::GET, "/users/charlie/repos"),
            Ok(None)
        ));
    }

    // TODO: check CEL programs
}
