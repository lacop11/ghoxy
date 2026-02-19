use axum::http::Request;
use axum::response::Response;
use axum::{body::Body, response::IntoResponse};

use crate::error::{ProxyError, ProxyResult};
use crate::user_agent;
use rules::RuleSet;
use tracing::info;

pub struct ProxyOptions {
    pub client_token_validator: client_auth::TokenValidator,
    pub github_token_provider: github_auth::GithubTokenProvider,
    pub ruleset_dir: std::path::PathBuf,
    pub github_base_url: String,
}

pub struct Proxy {
    client_token_validator: client_auth::TokenValidator,
    github_token_provider: github_auth::GithubTokenProvider,
    ruleset: RuleSet,
    github_base_url: String,
}

impl Proxy {
    pub async fn new(options: ProxyOptions) -> ProxyResult<Self> {
        Ok(Proxy {
            ruleset: RuleSet::from_directory(options.ruleset_dir)?,
            github_base_url: options.github_base_url,
            client_token_validator: options.client_token_validator,
            github_token_provider: options.github_token_provider,
        })
    }

    pub async fn refresh_jwks_periodically(&self, interval: std::time::Duration) {
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = self.client_token_validator.update_jwks().await {
                tracing::error!("Error refreshing JWKS: {}", e);
            }
        }
    }

    // Note on the weird "+ use<>", this is to prevent capturing self lifetime by default.
    // See https://blog.rust-lang.org/2024/09/05/impl-trait-capture-rules/#impl-traits-can-include-a-use-bound-to-specify-precisely-which-generic-types-and-lifetimes-they-use
    pub async fn handle_request(
        &self,
        req: Request<Body>,
    ) -> ProxyResult<impl IntoResponse + use<>> {
        // TODO: Better trace logging, what is safe to log? URL always safe, no secrets? Can we log some headers
        // (not the token!), and maybe the body (if not too big, no sensitive fields), especially for graphql
        // query we should log it.
        info!(method = ?req.method(), uri = ?req.uri(), "Handling request");

        // Extract JWT from auth header and check the claims.
        // This does not indicate the client is trusted but we can reject completely invalid tokens early.
        // Also, if the token is valid and from the trusted issuers we at least know the client's identity,
        // so if there is abuse we can tie them to a GCP service account or github user/org to investigate.
        let token = extract_bearer_token(&req)?;
        let claims = self.client_token_validator.validate(&token).await?;
        info!(claims = ?claims, "Claims parsed and valid (not yet trusted)");

        // First part of the path is the rule the client intends to use.
        let path = req
            .uri()
            .path()
            .strip_prefix("/")
            .ok_or(ProxyError::InvalidRequestPath)?;
        let first_segment = path
            .split('/')
            .next()
            .ok_or(ProxyError::InvalidRequestPath)?;
        // Note: this allows enumeration of valid rule names via response code and timing.
        // Does not seem like a concern so it's intentionally not addressed.
        let rule = self
            .ruleset
            .get_rule(first_segment)
            .ok_or(ProxyError::NoSuchRule(first_segment.to_string()))?;

        // For github terraform provider, if we override the base URL, it assumes we are using GHES
        // and changes the paths like this:
        //   /some/rest/route -> /api/v3/some/rest/route
        //   /graphql         -> /api/graphql
        // Rewrite back to what the path would be on api.github.com.
        let remaining_path = path
            .strip_prefix(first_segment)
            .ok_or(ProxyError::InvalidRequestPath)?;

        if let Some(rest_path) = remaining_path.strip_prefix("/api/v3/") {
            let api_path = format!("/{}", rest_path);
            // Check if user's provided claims allow them to use this rule at all,
            // and if yes find the subset of permissions that we should get a token for.
            let permissions = match rule.check_rest_request(&claims, req.method(), &api_path)? {
                Some(p) => p,
                None => return Err(ProxyError::RequestNotAllowedByRule),
            };
            info!(rule = first_segment, permissions = ?permissions, "Request allowed by rule");

            // Obtain token with the required permissions. This is cached, will only
            // create a new token if we don't have one with long enough remaining lifetime.
            let github_token = self
                .github_token_provider
                .get_installation_access_token(&permissions)
                .await?;

            let full_request_url = format!("{}{}", self.github_base_url, api_path);
            return proxy_validated_github_rest_request(
                &full_request_url,
                req.method().clone(),
                &github_token,
                req.into_body(),
            )
            .await;
        } else if remaining_path == "/api/graphql" {
            // TODO: check method is POST (or GET for introspection query).
            panic!("graphql not supported yet");
        }

        Err(ProxyError::InvalidRequestPath)
    }
}

fn extract_bearer_token(req: &Request<Body>) -> ProxyResult<String> {
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(ProxyError::MissingAuthorizationHeader)?;
    let auth_str = auth_header
        .to_str()
        .map_err(|_| ProxyError::InvalidAuthorizationHeader)?;
    let token = auth_str
        .strip_prefix("Bearer ")
        .ok_or(ProxyError::InvalidAuthorizationHeader)?;
    Ok(token.to_string())
}

async fn proxy_validated_github_rest_request(
    path: &str,
    method: http::Method,
    github_token: &str,
    _body: Body,
) -> ProxyResult<impl IntoResponse + use<>> {
    let client = reqwest::Client::new();
    // TODO: Do we need to proxy any headers?
    let req_builder = client
        .request(method.clone(), path)
        .bearer_auth(github_token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        // TODO: move to crate::user_agent constant including version number / repo path maybe.
        .header("User-Agent", user_agent::USER_AGENT);
    // TODO send body, if any.
    let response = req_builder
        .send()
        .await
        .map_err(ProxyError::HttpClientError)?;
    info!(path=path, method=?method, status=?response.status(), "Received response from github");
    let response_builder = Response::builder().status(response.status());
    // TODO: do we need to return any headers?
    response_builder
        .body(Body::from_stream(response.bytes_stream()))
        .map_err(ProxyError::HttpResponseError)
}
