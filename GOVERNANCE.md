# Governance

Small project, one maintainer. This file lists who holds access to sensitive
resources and how decisions are made.

## Members with access to sensitive resources

| Who | Role | Access |
| --- | ---- | ------ |
| [`marcoome`](https://github.com/marcoome) (Hostyt) | Maintainer | Repo admin, branch protection, org and repo secrets, container registry publishing (GHCR), release tagging and keyless signing (the `release.yml` workflow runs under the repo's OIDC identity) |
| `dependabot[bot]` | Bot | Opens dependency update PRs (Go modules, GitHub Actions, Docker base images, see [`.github/dependabot.yml`](.github/dependabot.yml)). No merge rights. |
| host-yt GitHub App | Bot | Used only by [`automerge.yml`](.github/workflows/automerge.yml) to squash-merge Dependabot PRs after every check passed. Short-lived token with contents, pull-requests and workflows write. Runtime major updates are left open for a human. |

Code ownership: [`.github/CODEOWNERS`](.github/CODEOWNERS).

## Responsibilities

Maintainer:

- Review and merge every change (squash, see [CONTRIBUTING.md](CONTRIBUTING.md)).
- Cut releases, keep the CHANGELOG and the tag versioning consistent.
- Triage issues and handle vulnerability reports per [SECURITY.md](SECURITY.md).
- Keep secrets, tokens and the App key rotated and scoped to what they need.

Bots only do what is listed in the table above; anything beyond that is a bug.

## Decisions

The maintainer decides. Discussion happens in issues and PRs; the reasoning for
non-obvious changes goes in the PR description or [docs/ROADMAP.md](docs/ROADMAP.md).
Breaking changes and security-relevant changes are called out in the CHANGELOG.

## Becoming a maintainer

There is no formal path yet. A contributor with a sustained record of good
changes and reviews can be invited by the current maintainer. New maintainers
get access to the minimum needed first (triage, then write); admin and
publishing credentials come last. Anyone granted write access or above must
have 2FA enabled on their GitHub account before access is granted.

## Revoking access

The maintainer removes a member's repo/org access and rotates every secret they
could read (registry tokens, App private key, API tokens). Access is also
removed on inactivity or a code of conduct violation
([CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)). Compromised bot credentials: revoke
the App installation or token, then rotate.
