# Security design

This proxy will, by design, have very sensitive access and thus will be desirable attack target.

## Threat model

The application stores a highly privileged GitHub App private key and exposes a public-facing HTTPS server.

The main threats considered by the design are:
- Obtaining the private key.
- Getting the server to execute (proxy) an unauthorized request.
- Getting the server to give out a valid GitHub access token for unauthorized reqeuest.
- Obtaining any valid token or request/response values of an authorized request by attacker.

## System design

### Key storage

The private key is stored in GCP KMS using HSM "protection level" (software KMS would work just as well, but for maximum security the server will refuse to work with non-HSM keys).

After the initial import the key will not be accessible and can only be used to sign access tokens. KMS access is restricted to the proxy server via GCP workload identity.

TODO: write and link the import procedure, this is critical step, must not leave the key behind on random developer disk where it can be stolen

### Client authentication

TODO: JWT/OIDC token validation logic

### Configurable permissions

TODO: rule syntax + validation logic

### Auditing

Every KMS operation is written to GCP audit logs. Every server request is logged as well.

TODO: kms iac audit logging setup


## Implementation considerations

To minimize risk we follow several rules for the implementation:

- Strict Rust use without `unsafe` or `unwrap` by default.
  - Exceptions need to be well justified in `expect` call.
  - Using `cargo clippy` and opting in into various extra strict checks.
- Minimal set of dependencies, using only widely used popular crates, not upgrading blindly to latest version to avoid supply-chain attacks.
  - Using `cargo-deny` to help with dependency graph management.
- Strict validation of all requests and minimal API surface.
  - If in doubt, reject.
- Distroless Docker image, running on gvisor GKE nodes, as non-privileged user.
- Relying only on workload identity for KMS access, no JSON keyfiles that could leak.
