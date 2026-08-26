# Rule authorization checked on non-canonical path; reqwest normalizes dot segments before forwarding

## Details
ghoxy authorizes requests by running rule regexes over the raw request path, but forwards a canonicalized path to GitHub, so the authorized path and the requested path differ.

Data flow: handle_request() takes req.uri().path() — the raw, percent-encoded, non-normalized request-target (hyper/axum perform no decoding or dot-segment removal, and server.rs installs no normalization layer). After stripping the rule name and the /api/v3 prefix, this raw string (api_path) is passed to rule.check_rest_request(), which regex-matches it literally (crates/rules/src/rule.rs:77). If a rule matches, a GitHub installation token with the rule's permissions is minted and the outbound request is built as format!("{}{}", github_base_url, api_path) and passed as &str to reqwest's client.request() (proxy.rs:188). reqwest parses this string with url::Url::parse (url 2.5.8, WHATWG URL algorithm), whose path parser resolves single- and double-dot segments — including the percent-encoded forms %2e, %2e%2e, .%2e and %2e. (ASCII case-insensitive) — before the request is serialized. GitHub therefore receives a path that was never checked against the rules.

Exploit examples:
1) With a realistic rule such as routes=["/repos/myorg/ci-repo/.*"], permissions=["contents:read"] (multi-segment wildcards are unavoidable for endpoints like /contents/{path} or /git/refs/{ref}), an authenticated client sends:
   GET /rule/api/v3/repos/myorg/ci-repo/../../../repos/myorg/secret-repo/contents/prod-secrets.tf
   The regex matches (path begins /repos/myorg/ci-repo/), a contents:read token is minted, and reqwest sends GET https://api.github.com/repos/myorg/secret-repo/contents/prod-secrets.tf. Because the installation token is not repository-scoped (provider.rs FIXME), the client reads any repo in the installation; write-permission rules (e.g. contents:write, issues:write, administration) similarly become installation-wide writes.
2) Even the shipped example rules with [^/]+ wildcards are affected, since [^/]+ matches '..' and '%2e%2e': POST /post-issue/api/v3/repos/%2e%2e/x/issues is checked as /repos/%2e%2e/x/issues (match, issues:write token minted) but forwarded as POST /x/issues — an arbitrary segment-collapsed endpoint the rule never authorized.

Excluding literal dots in rule regexes does not help because the WHATWG parser also treats the percent-encoded %2e variants as dot segments. Traversal cannot escape the api.github.com host (paths clamp at root), so this is an authorization bypass across GitHub API routes, not SSRF.

Root cause: the authorization decision uses a non-canonical URL path while the enforcement point (the outbound URL parser) canonicalizes it — a classic check/use representation mismatch (CWE-647).

## Evidence
1. [src/proxy.rs:96–122](https://github.com/lacop11/ghoxy/blob/main/src/proxy.rs#L96-L122)
   api_path is derived from the raw, percent-encoded, non-normalized request path (req.uri().path()); rule.check_rest_request() authorizes this literal string, then full_request_url is built by string concatenation from the same raw string and handed to the outbound HTTP client. The string that is regex-checked is not the string that ultimately reaches GitHub. This function is where the fix belongs: it produces both the checked and the forwarded representation.
2. [src/proxy.rs:186–189](https://github.com/lacop11/ghoxy/blob/main/src/proxy.rs#L186-L189)
   client.request(method, path) with a &str URL causes reqwest (0.13.1 per crates/ghoxy/Cargo.toml, via url 2.5.8 per Cargo.lock) to parse the URL with the WHATWG algorithm, which resolves dot segments in the path - including the percent-encoded forms %2e, %2e%2e, .%2e, %2e. (case-insensitive) - before sending. The request GitHub receives therefore has a different path than the one the rule authorized.
3. [src/proxy.rs:70–79](https://github.com/lacop11/ghoxy/blob/main/src/proxy.rs#L70-L79)
   Path extraction from req.uri().path(): axum/hyper deliver the raw request-target path with percent-encoding and dot segments intact; no normalization middleware is installed (server.rs installs only TraceLayer), so attacker-supplied dot segments reach the rule check verbatim.
4. [crates/rules/src/rule.rs:70–87](https://github.com/lacop11/ghoxy/blob/main/crates/rules/src/rule.rs#L70-L87)
   check_rest_request matches the path with anchored regexes via is_match on the literal string. Wildcards such as [^/]+ (used in all shipped example rules) match the segments '..' and '%2e%2e' because they contain no slash, so dot-segment paths pass the route check.
5. [example-rules/post-issue.toml:3–8](https://github.com/lacop11/ghoxy/blob/main/example-rules/post-issue.toml#L3-L8)
   Shipped example rule: routes = ["/repos/[^/]+/[^/]+/issues"], methods POST, permissions issues:write. POST /post-issue/api/v3/repos/%2e%2e/x/issues passes this rule but is forwarded as POST /x/issues - demonstrating checked path != sent path even with segment-restricted wildcards.
6. [crates/github-auth/src/provider.rs:96–100](https://github.com/lacop11/ghoxy/blob/main/crates/github-auth/src/provider.rs#L96-L100)
   The minted installation access token is scoped only by permission set, not by repository (FIXME notes the repositories restriction is unimplemented). Hence the route regexes in rules are the sole boundary confining a client to specific repos/resources; bypassing them lets the rule's permissions be exercised against any resource in the installation.

## Impact
The proxy's entire purpose is per-route authorization of GitHub API access; the bypass voids that guarantee. Confidentiality HIGH: read-permission rules (contents:read, members:read, etc.) become readable across every route/repo the installation token reaches. Integrity HIGH: write-permission rules (issues:write, contents:write) apply to arbitrary unauthorized routes. Availability NONE: no direct availability effect on the proxy. Subsequent-system impact: Impact lands on the GitHub organization behind the proxy: the minted installation token is permission-scoped but not repository-scoped, so bypassing route rules exposes and mutates org resources (private repo contents, issues, members data) far beyond what any rule intended.

## Reproduction steps
1. Attacker is any network client holding a valid OIDC token from an allowed issuer whose claims satisfy at least one rule's CEL check (the exact population the rules are meant to constrain) — PR LOW. One crafted HTTP request with dot segments (plain or %2e-encoded) suffices; no defenses to defeat (AC LOW), no user interaction. Reaching arbitrary API endpoints requires a rule whose route regex can span a '/' (e.g. .*), which is a ruleset-configuration condition — AT PRESENT; shipped [^/]+ rules still allow segment-collapse divergence.

## Recommended fix
1. The rule check runs on the raw request path while the outbound URL parser canonicalizes dot segments (including %2e-encoded forms) afterward, so the authorized path and the forwarded path can differ. Fix criteria: The byte string matched against rule regexes must be exactly the path sent upstream. E.g. parse the outbound URL first and run rules on the parsed url.path(), or reject any request whose path contains '.'/'..' segments or any percent-encoded variant ('%2e' case-insensitive) before rule matching, or verify post-parse that Url::parse(full_request_url).path() equals the checked api_path and fail closed otherwise. Verification: requests like /rule/api/v3/repos/a/%2e%2e/b and /repos/x/../y must either be rejected or be rule-checked in their canonical form.
2. Minted installation tokens are scoped only by permission set, not by repository, so any route-check bypass immediately grants installation-wide access (amplifies the bypass). Fix criteria: Defense in depth: installation access tokens are requested with an explicit repositories list derived from the matched rule (with the repo list included in the token cache key), so a path-check bypass cannot reach repositories outside the rule's intent.

---
**Severity:** HIGH
**Status:** Open
**Category:** Authorization bypass
**CWE:** [CWE-647](https://cwe.mitre.org/data/definitions/647.html)
**Repository:** lacop11/ghoxy
**Branch:** main
**Date created:** 2026-08-26

---

# Proxied authenticated responses strip Vary: Authorization, enabling cross-client shared-cache leakage

## Details
ghoxy authenticates and authorizes every request individually via the client's Authorization header (OIDC JWT checked against per-rule CEL claim programs), yet relays GitHub's response caching metadata verbatim while stripping GitHub's cache-partitioning header. GitHub's authenticated API responses carry 'Cache-Control: private, max-age=60, s-maxage=60', 'ETag', and 'Vary: Accept, Authorization, Cookie, X-GitHub-OTP'. ALLOWED_RESPONSE_HEADERS (proxy.rs:156-176) forwards Cache-Control, ETag, Date and Link but not Vary, and the relay loop (proxy.rs:212-218) adds no 'Vary: Authorization' or 'Cache-Control: no-store' of its own; server.rs applies no header middleware. The relayed 's-maxage=60' is one of the directives RFC 9111 s3.5 names as explicitly permitting shared caches to store responses to Authorization-bearing requests, so the only remaining guard is the single upstream-controlled 'private' directive, which ghoxy neither enforces nor supplements.

Exploit scenario: the documented deployment is a public-facing endpoint with external TLS termination (docs/SECURITY.md; todos: 'TLS must be external ... reverse proxy', GCP LB planned). If the fronting LB/CDN layer caches — e.g., GCP Cloud CDN FORCE_CACHE_ALL, Cloudflare 'Cache Everything', nginx proxy_cache with proxy_ignore_headers Cache-Control, or custom Varnish/Fastly VCL, all common configurations that override origin 'private' — the cache key is method+URL only, because ghoxy removed the 'Vary: Authorization' that would otherwise have partitioned entries per client even in those forced-cache modes (Cloud CDN, nginx, Varnish honor Vary). Victim client A, authorized by a rule, requests GET /rule/api/v3/orgs/X/members; the 200 response (org membership, repo settings, SSO emails — the project's stated use cases) is stored for 60s and renewable indefinitely via the relayed ETag (revalidation returns a fresh 200 from GitHub since If-None-Match is never forwarded upstream). Any other party then requesting the same URL within the window receives A's authorized response directly from the cache — without ghoxy performing token validation or rule evaluation at all, since cache hits never reach the origin. This is a cross-client confidentiality breach and authorization bypass squarely inside SECURITY.md's threat model ('Obtaining any ... request/response values of an authorized request by attacker'). Secondary effect: unauthenticated error responses (401/403/404 static strings from server.rs) also carry no anti-caching headers and can be cached over legitimate clients' requests in the same deployments.

Mitigating factor stated plainly: because 'private' is relayed, a fully RFC-9111-compliant shared cache in default configuration will not store these responses; exploitation requires a fronting cache configured to override origin directives. The defect is that ghoxy actively removes the second, deployment-robust layer (Vary: Authorization) that upstream GitHub provides, and forwards s-maxage which affirmatively invites shared caching. Related existing findings at this file cover the request path (path-normalization-rule-check-bypass-in-ghoxy-proxy); this is a distinct response-path sink.

## Evidence
1. [src/proxy.rs:156–176](https://github.com/lacop11/ghoxy/blob/main/src/proxy.rs#L156-L176)
   ALLOWED_RESPONSE_HEADERS relays GitHub's caching metadata verbatim (Cache-Control, ETag, Date, Link) but omits Vary. GitHub sends 'Vary: Accept, Authorization, Cookie, X-GitHub-OTP' on authenticated API responses; ghoxy strips it, removing the upstream's cache-partitioning protection while forwarding the freshness directives (max-age=60, s-maxage=60) that make the response look cacheable. Note s-maxage is one of the directives RFC 9111 s3.5 names as explicitly permitting shared caches to store responses to Authorization-bearing requests.
2. [src/proxy.rs:212–222](https://github.com/lacop11/ghoxy/blob/main/src/proxy.rs#L212-L222)
   The response relay loop copies only allowlisted headers from GitHub and adds no cache-partitioning or anti-caching header of ghoxy's own (no 'Vary: Authorization', no 'Cache-Control: no-store' override). The upstream Cache-Control value, including s-maxage=60, is passed through byte-for-byte.
3. [src/server.rs:133–138](https://github.com/lacop11/ghoxy/blob/main/src/server.rs#L133-L138)
   The axum router applies only TraceLayer; no middleware anywhere adds Vary or Cache-Control headers to proxied or error responses, confirming the proxy emits responses with GitHub's cache metadata and no partitioning.
4. [src/proxy.rs:62–67](https://github.com/lacop11/ghoxy/blob/main/src/proxy.rs#L62-L67)
   Clients authenticate per-request via the Authorization header (Bearer OIDC JWT). Authorization decisions therefore differ per client for the identical URL, which is exactly the situation an unpartitioned shared cache breaks: a cache hit is served without this code ever running, bypassing both token validation and rule evaluation.
5. [crates/rules/src/rule.rs:59–67](https://github.com/lacop11/ghoxy/blob/main/crates/rules/src/rule.rs#L59-L67)
   check_rest_request first evaluates the CEL claims program against the requesting client's JWT claims. Two clients with different claims get different allow/deny outcomes for the same method+path, establishing the victim/attacker differentiation that unkeyed caching erases.
6. [src/proxy.rs:147–155](https://github.com/lacop11/ghoxy/blob/main/src/proxy.rs#L147-L155)
   ALLOWED_REQUEST_HEADERS omits If-None-Match/If-Modified-Since, so ghoxy itself never generates 304s; but the relayed ETag allows a shared cache holding one client's response to successfully revalidate it against ghoxy (which re-fetches a full 200 from GitHub) and keep serving the entry to all clients beyond the initial 60s freshness window.

## Impact
Confidentiality HIGH: any rule-gated GitHub API response fetched by any authorized client (private org membership, SSO emails, repo settings) becomes readable by unauthorized parties for the cached window, bypassing both authentication and rule authorization. Integrity NONE: cached content originates from GitHub via the shared installation token and is identical regardless of requester; attacker cannot alter it. Availability NONE: cached error responses could mask service briefly but this is marginal and deployment-dependent. Severity held to MEDIUM rather than HIGH because the relayed 'private' directive protects all RFC-compliant default cache configurations; the flaw removes a second-layer defense.

## Reproduction steps
1. Attacker is any network client of the public-facing endpoint. Requires a deployment where the fronting LB/CDN caches despite the relayed 'private' directive (forced/override caching — a real but non-default condition), and a victim client fetching the target URL within the 60s (ETag-renewable) window; both are deployment/state conditions outside attacker control (AT PRESENT). On a cache hit the request never reaches ghoxy, so no valid JWT is needed (PR NONE), no user interaction (victim traffic is routine automation), no security mechanism must be defeated by the attacker (AC LOW).

## Recommended fix
1. The proxy relays upstream Cache-Control (including s-maxage, which explicitly authorizes shared caching of Authorization-authenticated responses) and ETag while stripping GitHub's 'Vary: Authorization', and never emits its own cache-partitioning or anti-caching directives, so per-client authorized responses are indistinguishable to a shared cache from publicly shareable ones. Fix criteria: Every response emitted by the proxy (success and error) must be safe for any shared cache: either set 'Cache-Control: private, no-store' (overriding, not relaying, the upstream value and never forwarding s-maxage/public), or include 'Vary: Authorization' on all responses so cache entries are partitioned by client credential. Verify that a Vary-respecting shared cache configured to cache aggressively cannot serve one client's response to a request bearing a different Authorization value, and that no relayed directive explicitly permits shared caching.
2. The relayed ETag lets a shared cache revalidate and renew a stored cross-client entry indefinitely, extending exposure beyond the 60-second freshness lifetime. Fix criteria: If ETag continues to be relayed for client-side revalidation, the anti-caching/partitioning headers above must make shared-cache storage or revalidation impossible; confirm a shared cache cannot extend an entry's lifetime via conditional requests to the proxy.

---
**Severity:** MEDIUM
**Status:** Open
**Category:** Sensitive data caching
**CWE:** [CWE-524](https://cwe.mitre.org/data/definitions/524.html)
**Repository:** lacop11/ghoxy
**Branch:** main
**Date created:** 2026-08-26

---

# GitHub installation tokens minted without repository scoping grant installation-wide access

## Details
GithubTokenProvider::create_installation_access_token (crates/github-auth/src/provider.rs) exchanges the app JWT for an installation access token by POSTing {"permissions": ...} without the "repositories"/"repository_ids" parameter. GitHub's documented behavior for this endpoint is that omitting the repository restriction yields a token scoped to ALL repositories the installation can access. The provider API (and the rules schema feeding it, crates/rules/src/rule.rs) has no way to express repository scope at all, and the moka cache is keyed only on the permission set, so every minted token is installation-wide for its permission scopes.

Data flow: an authenticated proxy client sends a request; rules map claims+method+path-regex to a Permissions set; get_installation_access_token mints/caches an installation-wide token; the proxy forwards the (regex-validated) request to GitHub bearing that token.

Because the token is never narrowed to the repositories a rule intends to grant, the anchored route regex in proxy.rs is the ONLY barrier between a least-privileged client and every repository of the installation — and that barrier is porous:

1) Traversal (independently verified on record): proxy.rs checks the raw, un-normalized path against the rule regex, then builds full_request_url and passes it to reqwest. reqwest's url crate (2.5.8) performs WHATWG dot-segment removal AFTER the check, treating '..', '.%2e', '%2e.', '%2e%2e' as dot segments. For a repo-pinned rule such as routes=["/repos/myorg/myrepo/contents/.*"] with permissions=["contents:read"], a client request to /rule/api/v3/repos/myorg/myrepo/contents/../../../../repos/otherorg/secretrepo/contents/secrets.yaml matches the regex (the .* spans the traversal) but is sent to GitHub as /repos/otherorg/secretrepo/contents/secrets.yaml. The installation-wide contents:read token authorizes it, exposing any repository in the installation. Even [^/]+ segments admit %2e%2e smuggling. Repository-scoped tokens would make GitHub itself reject such cross-repo requests; the missing scoping is what turns the path-check bypass into installation-wide access.

2) Wildcard rules: rules modeled on the shipped examples use /repos/[^/]+/[^/]+/... patterns (with an explicit 'TODO: restrict to repos' because the schema cannot express the restriction), so a client authorized to act on one project's repo can directly name any other repository of the installation and the token authorizes the operation (e.g. issues:write against every repo).

Root cause in scope: the minted credential's scope (all installation repositories) exceeds what the authorization rule granted, violating least privilege; the FIXME at provider.rs:98-99 acknowledges both the missing 'repositories' parameter and that repositories must become part of the cache key (a same-permissions cache hit would otherwise return a token broader/narrower than requested once scoping exists).

Impact: cross-repository read (contents/metadata) and write (e.g. issues, or whatever write scopes rules grant) across every repository the GitHub App installation covers, by a client that was only ever authorized for a single route/repository.

## Evidence
1. [crates/github-auth/src/provider.rs:86–103](https://github.com/lacop11/ghoxy/blob/main/crates/github-auth/src/provider.rs#L86-L103)
   The token-minting request POSTs to /app/installations/{id}/access_tokens with a JSON body containing only "permissions". The "repositories"/"repository_ids" field is omitted (acknowledged by the FIXME at lines 98-99). Per the GitHub API, omitting it makes the returned installation access token valid for EVERY repository the installation can access, at the requested permission levels.
2. [crates/github-auth/src/provider.rs:59–72](https://github.com/lacop11/ghoxy/blob/main/crates/github-auth/src/provider.rs#L59-L72)
   The cache key is only Permissions; there is no notion of repository scope anywhere in the provider API, so no caller can request a repo-restricted token even if it wanted to. All clients whose rules resolve to the same permission set share one installation-wide token.
3. [crates/rules/src/rule.rs:143–148](https://github.com/lacop11/ghoxy/blob/main/crates/rules/src/rule.rs#L143-L148)
   The rule file schema (methods/routes/permissions) has no repositories field, so administrators cannot express repository restriction in authorization rules; the only per-repo control any deployment can have is the route regex.
4. [src/proxy.rs:96–122](https://github.com/lacop11/ghoxy/blob/main/src/proxy.rs#L96-L122)
   The proxy's only enforcement between the client and the installation-wide token is the anchored route regex applied to the raw request path. The regex-checked path (api_path) is then concatenated into full_request_url and handed to reqwest, whose url-crate parsing performs WHATWG dot-segment normalization (`..`, `%2e%2e`) AFTER the check, letting a matched path resolve to a different repository/endpoint that the over-scoped token happily authorizes (this check-vs-use mismatch is independently verified on record).
5. [example-rules/post-issue.toml](https://github.com/lacop11/ghoxy/blob/main/example-rules/post-issue.toml) (whole file)
   Illustrative only (example rules are not loaded by production defaults; --ruleset-dir is a required operator-supplied flag): the shipped example grants issues:write for route /repos/[^/]+/[^/]+/issues and carries a TODO 'restrict to repos', documenting that repository restriction is intended but inexpressible in the schema; with the current provider every token minted for any rule of this shape can write issues in every repository of the installation.

## Impact
The proxy's core security function is scoping GitHub access. Exploitation exposes contents/metadata of every repository in the installation when any read-permission rule exists (C:HIGH for the data the proxy brokers) and permits writes limited to whatever write scopes rules grant (I:LOW, e.g. creating issues org-wide). No availability impact. Subsequent-system impact: The over-scoped credential acts on GitHub, a system beyond the proxy's boundary: all repositories of the GitHub App installation become readable at granted read scopes and writable at granted write scopes, regardless of which single repository the rule intended.

## Reproduction steps
1. Attacker is an onboarded proxy client: it must hold a valid OIDC token from an allowed issuer whose claims satisfy some rule (PR:LOW). It then crafts a path that the rule regex matches but that normalizes (dot-segment removal) or wildcards to another repository — no user interaction, plain HTTP requests over the network. Success depends on ruleset shape (a rule with .*/[^/]+ segments or reliance on the traversal), a deployment condition outside the attacker's control (AT:PRESENT). No built-in defense must be defeated beyond that (AC:LOW).

## Recommended fix
1. create_installation_access_token omits the repositories/repository_ids parameter when exchanging the app JWT, so GitHub returns a token valid for every repository of the installation — broader than any single rule's grant (least-privilege violation). Fix criteria: Every installation access token request must include the exact repository list (or repository_ids) that the matched authorization rule grants; a token minted for a rule scoped to repo X must be rejected by GitHub for any request against repo Y. Verify that the traversal/wildcard scenario now fails with 404/403 from GitHub even if the proxy's path check is bypassed.
2. The token cache is keyed only on Permissions, so once repository scoping exists (or if callers pass differing repo sets), differently-scoped requests would collide and one client could receive another's broader token. Fix criteria: The cache key must incorporate every parameter that affects token scope (permission set AND canonicalized repository list), so two requests differing in repository scope never share a cache entry. Verify a token cached for {contents:read, [repoA]} is never returned for {contents:read, [repoB]}.
3. The rules schema (crates/rules) cannot express repository restriction, forcing all deployments into installation-wide tokens and leaving route regexes as the only per-repo control. Fix criteria: Rule files can declare the repositories a rest rule applies to, that declaration is threaded through check_rest_request into the token request, and a rule without a repository declaration either fails validation or is explicitly marked all-repos. Verify the example rules' 'TODO: restrict to repos' scenario is expressible and enforced end to end.

---
**Severity:** MEDIUM
**Status:** Open
**Category:** Privilege escalation
**CWE:** [CWE-269](https://cwe.mitre.org/data/definitions/269.html)
**Repository:** lacop11/ghoxy
**Branch:** main
**Date created:** 2026-08-26

---

# Route regex anchoring wrapper broken by top-level alternation, allowing prefix/suffix matches

## Details
The rules crate promises fully anchored route regexes (rejecting explicit '^'/'$' and adding them automatically), but the anchoring is implemented as format!("^{}$", s). Regex alternation '|' has the lowest precedence, so any route pattern containing a top-level alternation compiles to a regex where only the first alternative is start-anchored and only the last is end-anchored.

Example: a rule author restricting a members listing to two orgs writes routes = ["/orgs/org1/members|/orgs/org2/members"] (the parenthesized form is only shown as an aside in a TODO comment; the validation error message tells authors anchors 'are always added automatically'). The compiled regex is ^/orgs/org1/members|/orgs/org2/members$.

Exploit: an attacker holding a token that satisfies the rule's claims sends GET /<rule>/api/v3/orgs/org1/members/12345/anything — this matches the first alternative as a bare prefix, so the request is authorized and forwarded with a token carrying the rule's permissions to an endpoint outside the allowlist (any GitHub endpoint under the /orgs/org1/members prefix, e.g. membership objects). Combined with the dot-segment normalization flaw (finding rule-path-check-vs-forward-url-normalization-mismatch), the trailing freedom becomes total: /orgs/org1/members/../../../ANY/PATH matches the prefix and is normalized by the url crate to /ANY/PATH, reaching ANY GitHub endpoint exercisable with the rule's permission scopes. Similarly, the suffix alternative matches any path ending in /orgs/org2/members.

A lesser variant of the same bug: a pattern ending in '\\' escapes the appended '$' into a literal dollar, silently removing the end anchor.

This is a latent flaw — the shipped example rules use parenthesized alternation — but it silently breaks the central security guarantee of the route-matching component for a natural pattern style that the crate's own error message and docs invite.

## Evidence
1. [crates/rules/src/rule.rs:124–129](https://github.com/lacop11/ghoxy/blob/main/crates/rules/src/rule.rs#L124-L129)
   anchored_regex() builds format!("^{}$", s) without wrapping the user pattern in a non-capturing group. For a pattern containing a top-level alternation 'a|b' the result is '^a|b$': the '^' binds only to the first alternative and '$' only to the last, so 'a' matches as an unanchored prefix and 'b' as an unanchored suffix. The starts_with('^')/ends_with('$') validation cannot detect this, yet the comment claims the regex is forced to be fully anchored.
2. [crates/rules/src/rule.rs:99–104](https://github.com/lacop11/ghoxy/blob/main/crates/rules/src/rule.rs#L99-L104)
   All rule route patterns from the TOML config flow through anchored_regex(); the resulting regexes are the sole route restriction applied to attacker-controlled request paths in check_rest_request (line 77).
3. [crates/rules/src/error.rs:23–24](https://github.com/lacop11/ghoxy/blob/main/crates/rules/src/error.rs#L23-L24)
   The error message actively instructs rule authors: 'remove ^/$, it is always added automatically' — creating a false guarantee that any pattern they write will be fully anchored.
4. [example-rules/get-users.toml:15–18](https://github.com/lacop11/ghoxy/blob/main/example-rules/get-users.toml#L15-L18)
   The documented rule-authoring guidance explicitly encourages alternation for restricting orgs ('with regex can do /orgs/(org1|org2)/members'); an author writing the natural unparenthesized form '/orgs/org1/members|/orgs/org2/members' silently gets an unanchored allowlist.

## Impact
The route allowlist degenerates to a substring prefix/suffix check, letting authorized-but-restricted clients reach GitHub endpoints outside the intended route set with the rule's minted installation token. Impact remains bounded by the GitHub permission scopes the rule grants (enforced server-side by GitHub), hence LOW confidentiality/integrity.

## Reproduction steps
1. Requires a deployment whose rule config uses a top-level '|' in a route pattern (not present in shipped examples, but a natural authoring style the docs suggest) — a deployment condition outside the attacker's control. Given such a rule, an attacker with any token satisfying the rule's claims sends a single crafted path with the allowlisted string as prefix/suffix; no user interaction or defense evasion needed.

## Recommended fix
anchored_regex() concatenates '^' and '$' around the raw pattern; alternation precedence (and a trailing backslash) can detach the anchors from parts of the pattern, violating the full-anchoring guarantee the function claims to enforce. Fix criteria: Every compiled route regex must match only when the entire path matches the author's pattern, for all syntactically valid patterns including top-level alternation. E.g. wrap the pattern in a non-capturing group ('^(?:pat)$') or use RegexBuilder/Anchored matching. Verify: a rule with route 'a|b' does not match 'aX' or 'Xb', and a pattern ending in a backslash is rejected or handled correctly.

---
**Severity:** MEDIUM
**Status:** Open
**Category:** Permissive regular expression
**CWE:** [CWE-625](https://cwe.mitre.org/data/definitions/625.html)
**Repository:** lacop11/ghoxy
**Branch:** main
**Date created:** 2026-08-26

---

# JWKS refresh aborts on first issuer failure, leaving stale keys trusted for other issuers

## Details
TokenValidator::update_jwks() (crates/client-auth/src/validator.rs:48-51) refreshes the cached JWKS for every allowed issuer in a single loop and propagates the first fetch error with `?`. `cached_jwks` is a std HashMap whose key set is fixed at construction, so iteration order is arbitrary but stable for the process lifetime: when one issuer's OIDC discovery/JWKS fetch fails, the loop returns early and every issuer that iterates after it keeps its previous key set — on that pass and on every subsequent pass, since the periodic caller (Proxy::refresh_jwks_periodically, crates/ghoxy/src/proxy.rs:42-49) only logs the error and retries, aborting at the same point each cycle.

Startup is fail-fast (crates/ghoxy/src/server.rs:99-101 propagates the initial update_jwks error and aborts server creation), so a misconfigured or decommissioned issuer URL cannot get past startup. The exploitable condition is an issuer that was reachable at startup becoming persistently unreachable while the process runs (e.g. a prolonged IdP outage): with the default configuration of two public issuers (Google and GitHub Actions OIDC, crates/ghoxy/src/bin/server.rs:23-28), an outage of one freezes the other's key set for the remainder of the process lifetime whenever iteration order places the failing issuer first.

Security consequences: (1) keys a healthy issuer rotated out — including keys rotated specifically because they were compromised — remain trusted by validate() (validator.rs:96-108 accepts any kid present in the cached set) for as long as the refresh keeps aborting before reaching that issuer, extending the window in which an attacker holding such a key can forge accepted client tokens; (2) newly published keys are not picked up, so legitimate tokens signed with new keys are rejected (availability degradation of the authentication path). An anonymous client cannot cause an issuer fetch to fail, so this is a fail-degraded weakness contingent on runtime conditions, not a directly attacker-triggerable one — hence LOW severity. The mechanism (`?` coupling independent issuers) is clearly unintended: the design deliberately keeps serving from cache when an issuer's own refresh fails, but nothing suggests one issuer's failure was meant to block the others' rotation pickup.

## Evidence
1. [crates/client-auth/src/validator.rs:48–50](https://github.com/lacop11/ghoxy/blob/main/crates/client-auth/src/validator.rs#L48-L50)
   The refresh loop iterates the issuer HashMap (order arbitrary but fixed per process, since the key set never changes after construction) and uses `?` on the per-issuer fetch: the first failing issuer aborts the entire update, so issuers later in the iteration are never refreshed — on this pass or any later one while the failure persists. This is the code the fix must change.
2. [crates/client-auth/src/validator.rs:96–107](https://github.com/lacop11/ghoxy/blob/main/crates/client-auth/src/validator.rs#L96-L107)
   validate() accepts a signature from any kid present in the cached key set; keys the issuer rotated out (e.g. after a compromise) remain trusted for as long as refresh keeps aborting before reaching that issuer, and newly published keys are never picked up.
3. [src/proxy.rs:42–49](https://github.com/lacop11/ghoxy/blob/main/src/proxy.rs#L42-L49)
   The periodic refresh task only logs the error and retries after the interval; with a persistently failing issuer the abort repeats at the same iteration point every cycle, so the other issuers' key sets stay stale for the process lifetime.
4. [src/server.rs:99–101](https://github.com/lacop11/ghoxy/blob/main/src/server.rs#L99-L101)
   Startup fail-fasts on the initial update_jwks error, so a misconfigured issuer cannot reach the running state; the exploitable condition is therefore an issuer becoming unreachable after successful startup (e.g. an IdP outage), and a restart during the outage fails closed rather than running stale.

## Impact
Impact is an extended trust window for rotated-out keys (bounded weakening of authentication, contingent on the attacker holding such a key) and rejection of legitimate tokens signed with newly rotated-in keys during the stale period (partial availability loss of the authentication path).

## Reproduction steps
1. The token-validation sink is network-reachable by anonymous clients and no defense must be defeated (attack complexity LOW), but exploitation depends on runtime conditions outside the attacker's control (attack requirements PRESENT): an allowed issuer must become persistently unreachable after a successful fail-fast startup, the per-process HashMap iteration order must place the failing issuer before the victim issuer, the process must not restart during the window, and for the integrity consequence the attacker must already possess a signing key the victim issuer rotated out. No privileges or user interaction are needed.

## Recommended fix
Error handling in update_jwks couples independent issuers: a single issuer's fetch failure aborts refresh for all remaining issuers (arbitrary HashMap order), so key rotation (including removal of compromised keys) is not honored for healthy issuers. Fix criteria: A refresh failure for one issuer must not prevent refreshing the key sets of other issuers: each issuer is attempted independently per refresh cycle, failures are reported per issuer, and successful fetches always replace that issuer's cache. Verify that with one issuer permanently unreachable, the other issuers' JWKS still track rotations (old kids dropped, new kids added) on the next refresh.

---
**Severity:** LOW
**Status:** Open
**Category:** Use of expired key
**CWE:** [CWE-324](https://cwe.mitre.org/data/definitions/324.html)
**Repository:** lacop11/ghoxy
**Branch:** main
**Date created:** 2026-08-26
