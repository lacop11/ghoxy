use crate::Result;

/// Validated and parsed JWT claims.
///
/// Has special handling for known issuers.
#[derive(Debug)]
pub struct Claims {
    /// Parsed and validated claims from known issuers, if applicable.
    pub known: Option<KnownClaims>,
    /// All of the token claims, unparsed. Prefer to use the known claims.
    pub raw_claims: serde_json::Value,
}

#[derive(Debug)]
pub enum KnownClaims {
    GoogleServiceAccount(GoogleServiceAccountClaims),
    GithubActions(GithubActionsClaims),
}

/// Parsed GCP "Service account ID token"
///
/// Refer to https://docs.cloud.google.com/docs/authentication/token-types#sa-id-tokens
/// Must be obtained with the include_email option enabled.
#[derive(Debug)]
pub struct GoogleServiceAccountClaims {
    /// Verified email of the service account.
    pub verified_email: String,
    /// Service account unique id, from the subject claim.
    pub service_account_id: String,
    /// Service account that requested the token.
    pub authorized_party_id: String,
}

impl GoogleServiceAccountClaims {
    fn from_raw_claims(raw: &serde_json::Value) -> Result<Self> {
        if raw.get("iss").and_then(|v| v.as_str()) != Some("https://accounts.google.com") {
            return Err(crate::Error::TokenClaimMissingOrInvalid("iss"));
        }

        if raw.get("email_verified").and_then(|v| v.as_bool()) != Some(true) {
            return Err(crate::Error::TokenClaimMissingOrInvalid("email_verified"));
        }

        Ok(Self {
            verified_email: get_non_empty_claim(raw, "email")?,
            service_account_id: get_non_empty_claim(raw, "sub")?,
            authorized_party_id: get_non_empty_claim(raw, "azp")?,
        })
    }
}

//  raw_claims: Object {
//         "actor": String("octocat"),
//         "actor_id": String("12345678"),
//         "aud": String("https://gaap.example.com"),
//         "base_ref": String(""),
//         "check_run_id": String("12345678901"),
//         "enterprise": String("octo-enterprise"),
//         "enterprise_id": String("12345"),
//         "event_name": String("push"),
//         "exp": Number(1769181528),
//         "head_ref": String(""),
//         "iat": Number(1769181228),
//         "iss": String("https://token.actions.githubusercontent.com"),
//         "job_workflow_ref": String("octo-org/octo-repo/.github/workflows/dump.yaml@refs/heads/main"),
//         "job_workflow_sha": String("0123456789abcdef0123456789abcdef01234567"),
//         "jti": String("00000000-0000-0000-0000-000000000000"),
//         "nbf": Number(1769180928),
//         "ref": String("refs/heads/main"),
//         "ref_protected": String("false"),
//         "ref_type": String("branch"),
//         "repository": String("octo-org/octo-repo"),
//         "repository_id": String("123456789"),
//         "repository_owner": String("octo-org"),
//         "repository_owner_id": String("87654321"),
//         "repository_visibility": String("private"),
//         "run_attempt": String("1"),
//         "run_id": String("10987654321"),
//         "run_number": String("9"),
//         "runner_environment": String("github-hosted"),
//         "sha": String("0123456789abcdef0123456789abcdef01234567"),
//         "sub": String("repo:octo-org/octo-repo:ref:refs/heads/main"),
//         "workflow": String("Dump token for testinf"),
//         "workflow_ref": String("octo-org/octo-repo/.github/workflows/dump.yaml@refs/heads/main"),
//         "workflow_sha": String("0123456789abcdef0123456789abcdef01234567"),
//     },

/// Parsed GitHub Actions OIDC token claims.
///
/// Refer to https://docs.github.com/en/actions/reference/security/oidc
#[derive(Debug)]
pub struct GithubActionsClaims {
    // TODO: Add docs for the fields.
    pub actor: String,
    pub repository: String,
    pub event_name: String,
    pub sha: String,
    // TODO: Add more / all custom github fields.
}

impl GithubActionsClaims {
    fn from_raw_claims(raw: &serde_json::Value) -> Result<Self> {
        Ok(Self {
            actor: get_non_empty_claim(raw, "actor")?,
            repository: get_non_empty_claim(raw, "repository")?,
            event_name: get_non_empty_claim(raw, "event_name")?,
            sha: get_non_empty_claim(raw, "sha")?,
        })
    }
}

impl Claims {
    pub(crate) fn from_raw_claims(raw: &serde_json::Value) -> Result<Self> {
        let known = match raw.get("iss").and_then(|v| v.as_str()) {
            Some("https://accounts.google.com") => Some(KnownClaims::GoogleServiceAccount(
                GoogleServiceAccountClaims::from_raw_claims(raw)?,
            )),
            Some("https://token.actions.githubusercontent.com") => Some(
                KnownClaims::GithubActions(GithubActionsClaims::from_raw_claims(raw)?),
            ),
            _ => None,
        };
        Ok(Claims {
            known,
            raw_claims: raw.clone(),
        })
    }
}

fn get_non_empty_claim(raw: &serde_json::Value, claim_name: &'static str) -> Result<String> {
    let claim_value = raw
        .get(claim_name)
        .and_then(|v| v.as_str())
        .ok_or_else(|| crate::Error::TokenClaimMissingOrInvalid(claim_name))?
        .to_string();
    if claim_value.is_empty() {
        return Err(crate::Error::TokenClaimMissingOrInvalid(claim_name));
    }
    Ok(claim_value)
}

// TODO: Some basic tests for the claims parsing.
