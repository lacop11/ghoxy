use axum::http::Request;
use axum::{body::Body, response::IntoResponse};

use crate::error::{Error, Result};
use rules::{RestMethod, RuleSet};

pub struct ProxyOptions {
    pub ruleset_dir: std::path::PathBuf,
    pub token_validator: client_auth::TokenValidator,
}

pub struct Proxy {
    ruleset: RuleSet,
    token_validator: client_auth::TokenValidator,
}

impl Proxy {
    pub async fn new(options: ProxyOptions) -> Result<Self> {
        Ok(Proxy {
            ruleset: RuleSet::from_directory(options.ruleset_dir)?,
            token_validator: options.token_validator,
        })
    }

    // Note on the weird "+ use<>", this is to prevent capturing self lifetime by default.
    // See https://blog.rust-lang.org/2024/09/05/impl-trait-capture-rules/#impl-traits-can-include-a-use-bound-to-specify-precisely-which-generic-types-and-lifetimes-they-use
    pub async fn handle_request(&self, req: Request<Body>) -> Result<impl IntoResponse + use<>> {
        // TODO: proper tracing. we can't log full request/response, only the safe metadata
        // method+url for request should be ok
        dbg!(&req);

        // Extract JWT from auth header and check the claims.
        // This does not indicate the client is trusted but we can reject completely invalid tokens early.
        // Also, if the token is valid and from the trusted issuers we at least know the client's identity,
        // so if there is abuse we can tie them to a GCP service account or github user/org to investigate.
        let token = extract_bearer_token(&req)?;
        let claims = self.token_validator.validate(&token).await?;
        dbg!(&claims);

        // First part of the path is the rule the client intends to use.
        let path = req
            .uri()
            .path()
            .strip_prefix("/")
            .ok_or(Error::InvalidRequestPath)?;
        let first_segment = path.split('/').next().ok_or(Error::InvalidRequestPath)?;
        // Note: this allows enumeration of valid rule names via response code and timing.
        // Does not seem like a concern so it's intentionally not addressed.
        let rule = self.ruleset.get_rule(first_segment).ok_or(Error::NoSuchRule(first_segment.to_string()))?;

        // For github terraform provider, if we override the base URL, it assumes we are using GHES
        // and changes the paths like this:
        //   /some/rest/route -> /api/v3/some/rest/route
        //   /graphql         -> /api/graphql
        // Rewrite back to what the path would be on api.github.com.
        let remaining_path = path
            .strip_prefix(first_segment)
            .ok_or(Error::InvalidRequestPath)?;

        if let Some(rest_path) = remaining_path.strip_prefix("/api/v3/") {
            let api_path = format!("/{}", rest_path);
            let api_method = match req.method() {
                &axum::http::Method::GET => RestMethod::Get,
                &axum::http::Method::POST => RestMethod::Post,
                // TODO: Other methods.
                _ => return Err(Error::UnsupportedHttpMethod(req.method().to_string())),
            };

            // Check if user's provided claims allow them to use this rule at all,
            // and if yes find the subset of permissions that we should get a token for.
            let permissions = match rule.check_rest_request(&claims, &api_method, &api_path)? {
                Some(p) => p,
                None => return Err(Error::RequestNotAllowedByRule),
            };
            dbg!(&permissions);

            // TODO forward request, proxy response
            return Ok("TODO".to_string());
        } else if remaining_path == "/api/graphql" {
            // TODO: check method is POST (or GET for introspection query).
            panic!("graphql not supported yet");
        }
        return Err(Error::InvalidRequestPath);
    }
}

fn extract_bearer_token(req: &Request<Body>) -> Result<String> {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(Error::MissingAuthorizationHeader)?;
    let auth_str = auth_header.to_str().map_err(|_| Error::InvalidAuthorizationHeader)?;
    let token = auth_str
        .strip_prefix("Bearer ")
        .ok_or(Error::InvalidAuthorizationHeader)?;
    Ok(token.to_string())
}
