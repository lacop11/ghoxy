# GAAP: GitHub Auth API Proxy

A proxy between your IaC provisioning, Actions workflows or other automation and GitHub itself. Provides a much finer control over permissions and removes the need to keep creating new GitHub Apps for every tiny usecase.

## Motivation

The GitHub API permission system sucks.

To be able to use certain APIs you often have to grant a lot more access than you would like, for example:

- To *read* [repository settings](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository) (like `allow_squash_merge`) you need to have *write access to repository contents*. That means to even run `terraform plan` on a `github_repository` resources across organization would need org-wide code write access.

- To get the SSO email for organization member you need organization admin permissions that also includes a lot more things.

On top of that, the only secure authentication method is to use GitHub Apps, but then you are faced with the problem of storing the app private key somewhere. And in order to provide the least privilege to every workflow, you will soon end up with dozens of apps that are a hassle to create and maintain.

## Solution

This project provides a transparent proxy with much finer-grained access control.

Clients will connect to this proxy instead of `api.github.com`. Since on-prem GitHub enterprise exists the [Terraform provider](https://registry.terraform.io/providers/integrations/github/latest/docs) as well as most API libraries already support overriding the base URL.

To authenticate clients provide an OIDC token. You can get this in context of GitHub Actions without storing any long-term secrets, and you can use other providers as well (such as [GCP Workload Identity](https://docs.cloud.google.com/iam/docs/workload-identity-federation)).

You only need to create a single GitHub App that has the superset of all the permissions you will need, and then configure rules that grant only the barest minimum to every usecase. While this seems risky, this single app's private key will be stored in HSM and only used to sign short-lived tokens which is probably much better than what you would be doing otherwise (such as storing it in GitHub Actions secrets where it's trivial to exfiltrate).

## TODO

extra stuff in here:
- requirements, sample repo setup
links to additional documents:
- intitial setup (provision KMS, import the wrapped key, spin up k8s service etc)
- design doc / security
- configuration reference
