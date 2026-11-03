# Ghoxy: GitHub API proxy with better authentication

> [!CAUTION]
> This is an unfinished prototype, not suitable for use.

A proxy between your IaC provisioning, Actions workflows or other automation and GitHub itself. Provides a much finer control over permissions and removes the need to keep creating new GitHub Apps for every tiny usecase.

## Motivation

The GitHub API permission system sucks.

To be able to use certain APIs you often have to grant a lot more access than you would like, for example:

- To *read* [repository settings](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository) (like `allow_squash_merge`) you need to have *write access to repository contents*. That means to even run `terraform plan` on a `github_repository` resources across organization would need org-wide code write access.

- To get the SSO email for organization member you need organization admin permissions that also includes a lot more things.

- And more examples in long-standing open issues such as https://github.com/dear-github/dear-github/issues/113. Do not expect GitHub to fix this.

On top of that, the only secure authentication method is to use GitHub Apps, but then you are faced with the problem of storing the app private key somewhere. And in order to provide the least privilege to every workflow, you will soon end up with dozens of apps that are a hassle to create and maintain.

## Solution

This project provides a transparent proxy with much finer-grained access control.

Clients will connect to this proxy instead of `api.github.com`. Since on-prem GitHub enterprise exists the [Terraform provider](https://registry.terraform.io/providers/integrations/github/latest/docs) as well as most API libraries already support overriding the base URL.

To authenticate clients provide an OIDC token. You can get this in context of GitHub Actions without storing any long-term secrets, and you can use other providers as well (such as [GCP Workload Identity](https://docs.cloud.google.com/iam/docs/workload-identity-federation)).

You only need to create a single GitHub App that has the superset of all the permissions you will need, and then configure rules that grant only the barest minimum to every usecase. While this seems risky, this single app's private key will be stored in HSM and only used to sign short-lived tokens which is probably much better than what you would be doing otherwise (such as storing it in GitHub Actions secrets where it's trivial to exfiltrate).

## Pior art

There are two existing projects in this area, `magic-github-proxy` and `octo-sts`. Why do we need Ghoxy?

- [magic-github-proxy](https://github.com/google/magic-github-proxy) handles the proxying but it relies on the client providing a JWT token that encodes the allowed scopes (routes and methods).

    This means you need to have some other service that decides who can get what tokens, for example if you want to allow GitHub Actions workflows on certain repos or branches to access a given scope.

    Additionally, the project is archived and unmaintained, and it lacks proper documentation. Lastly, it expects the private key available as a file and has no KMS support.

- [octo-sts](https://github.com/octo-sts/app) uses config files with OIDC claim matching to authorize clients (like Ghoxy), stores the key in KMS and appears to be (as of January 2026) actively maintained.

    However, it takes a different approach to the problem. Instead of proxying requests it just issues a scoped-down token returned to client who then talks to the GitHub API directly.

    This solves the problem of "I need to create another app for this workflow" but not the problem of permission granularity. For example if you want to view repository settings you still need to be given a token for writing contents, and nothing can stop the client from abusing it.

Ghoxy tries to combine the best aspects of both of these projects, giving you fine-grained access control, secure KMS storage and no need for additional services, relying only on config files identifying clients by OIDC claims.

## TODO

extra stuff in here:
- requirements, sample repo setup
links to additional documents:
- intitial setup (provision KMS, import the wrapped key, spin up k8s service etc)
- design doc / security
- configuration reference
