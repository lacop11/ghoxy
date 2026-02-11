use axum::http::Request;
use axum::{body::Body, response::IntoResponse};

use crate::error::{Error, Result};

pub struct Proxy {
    // ruleset: crate::rules::RuleSet,
}

impl Proxy {
    // pub async fn new(options: ProxyOptions) -> Result<Self> {
    //     Proxy { ruleset }
    // }

    // Note on the weird "+ use<>", this is to prevent capturing self lifetime by default.
    // See https://blog.rust-lang.org/2024/09/05/impl-trait-capture-rules/#impl-traits-can-include-a-use-bound-to-specify-precisely-which-generic-types-and-lifetimes-they-use
    pub async fn handle_request(&self, req: Request<Body>) -> Result<impl IntoResponse + use<>> {
        // TODO: proper tracing. we can't log full request/response, only the safe metadata
        // method+url for request should be ok
        dbg!(&req);

        // First part of the path is the rule the client intends to use.
        let path = req
            .uri()
            .path()
            .strip_prefix("/")
            .ok_or(Error::InvalidRequestPath)?;
        let first_segment = path.split('/').next().ok_or(Error::InvalidRequestPath)?;
        // Note: this allows enumeration of valid rule names via response code and timing.
        // Does not seem like a concern so it's intentionally not addressed.
        // TODO rule = self.ruleset.get_rule(first_segment).ok_or(Error::NoSuchRule(first_segment.to_string()))?;

        // For github terraform provider, if we override the base URL, it assumes we are using GHES
        // and changes the paths like this:
        //   /some/rest/route -> /api/v3/some/rest/route
        //   /graphql         -> /api/graphql
        // Rewrite back to what the path would be on api.github.com.
        let api_path;
        let remaining_path = path
            .strip_prefix(first_segment)
            .ok_or(Error::InvalidRequestPath)?;

        if let Some(rest_path) = remaining_path.strip_prefix("/api/v3/") {
            api_path = ApiPath::Rest(format!("/{}", rest_path));
        } else if remaining_path == "/api/graphql" {
            api_path = ApiPath::Graphql;
        } else {
            return Err(Error::InvalidRequestPath);
        }

        // TODO get token claims
        // TODO validate against rule
        // TODO find permissions for route based on method+path, if allowed
        // TODO forward request, proxy response

        // panic!("graphql not supported yet");

        return Ok("TODO".to_string());
    }
}

enum ApiPath {
    Rest(String),
    Graphql,
}
