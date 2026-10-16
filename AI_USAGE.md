# AI usage

This project is developed with AI coding assistants. This page states how, so
users, contributors and funders can judge the provenance of the code.

## Tools

- **Claude Code** (Anthropic): writing and changing code, tests and docs from the
  maintainer's instructions, searching the codebase, and drafting reviews.
- **OpenAI Codex**: second-opinion code review and some implementation work. Until
  October 2026 it also ran as an automated pull request reviewer.

## What the maintainer does

The maintainer, not the assistants, is responsible for:

- architecture, feature scope and trade-offs (for example tenant isolation,
  the WireGuard L3 design, and fail-closed defaults);
- deciding what is merged and released;
- reviewing every change, including security-sensitive paths;
- testing on real deployments (production nodes, upgrades, failover, TLS issuance);
- answering issues and handling security reports.

## How AI-assisted changes are checked

Every change, whoever or whatever wrote it, goes through the same gates before
it reaches `main`:

- pull request with the required CI checks: build, unit and integration tests
  (SQLite and MySQL/MariaDB), Terraform provider tests, image builds;
- security scanning: CodeQL, semgrep, gitleaks, trivy, zizmor;
- manual review, plus a live test on a running install for anything that touches
  TLS, routing, tenant boundaries or node configuration.

AI output is never treated as correct by default. Review findings are verified
against the code before they are fixed or dismissed.

## Attribution in history

Some commits carry a `Co-Authored-By` trailer or a "Generated with" line naming
an assistant. Not every AI-assisted commit has one, so read the trailer as a
hint, not a complete record. This page is the authoritative statement.

## Contributors

Outside contributions come in through issues (see `CONTRIBUTING.md`). If an AI
tool helped write a report or a proposed patch, say so, and check that what you
send is accurate and reproducible.
