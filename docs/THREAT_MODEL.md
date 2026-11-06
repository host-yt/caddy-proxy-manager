# Threat Model

Scope: the panel (`cmd/server`), remote Caddy nodes, node agents (`cmd/node-agent`),
the WireGuard mesh, and the release pipeline. Controls are detailed in
[SECURITY.md](SECURITY.md); components and data flow in [ARCHITECTURE.md](ARCHITECTURE.md).
Out of scope: physical host access, kernel exploits, cloud provider compromise.

## Assets

| Asset | Where | Protection |
|-------|-------|-----------|
| Database (tenants, routes, audit log) | MariaDB/MySQL or SQLite | Network-restricted; per-tenant `client_id` filtering |
| Encrypted secrets (WG keys, DNS provider credentials, TOTP seeds, install-state DB credentials) | DB columns, `install_state.json` | AES-256-GCM, key derived from `APP_SECRET`; `cmd/rotate-secret` |
| Passwords, API key hashes, recovery codes | DB | Argon2id |
| TLS private keys (ACME, manual certs, mTLS CAs) | Caddy storage / DB | Node filesystem permissions; manual-cert and CA keys encrypted at rest |
| Node join tokens and per-node agent tokens | DB (hash), node env | Single-use, expiring join tokens; agent tokens stored as SHA-256 hashes |
| WireGuard keys and preshared keys | DB (encrypted), node | AES-256-GCM; PSK on both mesh and customer tunnels |
| Caddy admin API (full node config) | Node `:2019` | No auth of its own; reachability only (see risks) |
| Release artifacts (images) | GHCR / Docker Hub | Signing and provenance (see Supply chain) |

## Actors and trust boundaries

| Actor | Trust | Boundary |
|-------|-------|----------|
| Internet clients (visitors to proxied hosts) | Untrusted | Caddy edge: TLS, optional WAF, rate limits, mTLS |
| Anonymous panel visitors | Untrusted | Panel login, CSRF, rate limiting, CAPTCHA |
| Clients (tenants) | Low: trusted only for own resources | Role + `client_id` scoping; tenant-editable config is allow-listed |
| Resellers | Medium: trusted only inside their boundary | Reseller boundary allow-list; cannot scope to or act on platform admins |
| Platform admins | High | 2FA enforcement, audit log, authorization epoch |
| Remote nodes / node agents | Semi-trusted: authenticated, attributed only to what they serve | Per-node token; ingest scoped to the node's routes; WireGuard mesh |
| Caddy admin API | Fully trusted by anything that reaches it | Network isolation (compose network / WireGuard address) |
| CI / release pipeline | High | Pinned actions, minimal permissions, signed images |
| Third parties (DNS APIs, ACME, OIDC, SMS, webhooks) | Untrusted responses | Outbound calls use an SSRF-guarded client |

## Top threats

Ranked by likelihood x impact (highest first).

| # | Threat | Existing mitigation | Residual risk |
|---|--------|---------------------|---------------|
| 1 | **Tenant isolation failure / IDOR**: one tenant reads or changes another's routes, certs, keys or logs | Role middleware; client handlers filter by `client_id`; reseller boundary allow-list; session and API-key invalidation on privilege change (authorization epoch); node ingest attributed only to routes the node serves | New endpoints must apply the same scoping; reviewed per feature |
| 2 | **Credential theft / account takeover** (phishing, brute force, stolen session or API key) | Argon2id; Redis lockout and rate limits; TOTP, passkeys, OTP; admin 2FA enforcement; HttpOnly sessions, rotated on login; scoped API keys with RPM cap; audit log | Admin 2FA is configurable and not forced by default; OIDC provider tokens are not revocation-checked after login |
| 3 | **Node compromise**: stolen agent token or host takeover | Join tokens single-use and expiring; per-node token; node can only write about its own routes; WireGuard isolation; panel is sole config writer | A compromised node exposes the TLS keys and traffic it serves |
| 4 | **Caddy admin API reachability**: anyone who can reach `:2019` controls that node | Port never published on the manager stack; remote nodes bind it to the WireGuard address; agent admin proxy with panel-issued key; tenant config cannot target it (custom-handler allow-list, L4 deny set) | The API has no authentication of its own; nodes not yet migrated to the agent proxy rely on network isolation alone. Documented in [SECURITY.md](SECURITY.md#caddy-admin-api---known-limitation) |
| 5 | **SSRF from backend or DNS features** (upstreams, webhooks, SIEM forwarding, DNS providers, L4 streams, external upstreams) | Safe HTTP client blocks loopback/RFC1918 for outbound calls; `EXTERNAL_UPSTREAM_ALLOWLIST`; L4 infrastructure deny set with resolve-once pinning and quarantine; DNS-TXT ownership proof for domains and aliases | Private upstreams are allowed by design (tenants proxy to private backends); operators should firewall the proxy's reachable networks |
| 6 | **Supply chain**: malicious dependency, base image or release tampering | Go modules with `go.sum`; Dependabot (gomod, docker, actions); actions and base images pinned by digest; vulnerability scans and OpenSSF Scorecard in CI; per-arch images with SBOM and provenance; cosign keyless signature and build attestation on release | Upstream Caddy modules are third-party code compiled into node images |
| 7 | **Secret disclosure at rest** (DB dump, backup, disk theft) | AES-256-GCM envelope with purpose binding; `APP_SECRET` length enforced; secret rotation tool; Argon2id for hashes | Route records (hostnames, upstreams) are stored in plaintext; loss of `APP_SECRET` plus a DB dump exposes the encrypted columns |
| 8 | **WAF bypass** | Coraza with OWASP CRS, per-route mode and suppressions; WAF events reported to the panel; defense in depth with rate limits and mTLS | The WAF is a probabilistic filter; it is not a substitute for backend hardening. Detection-only mode logs but does not block |
| 9 | **Denial of service** (edge flooding, panel login floods, resource exhaustion by one tenant) | Redis sliding-window limits (login, `/internal/ask`, unauthenticated POST, API key, AI); quotas per tenant; optional Cloudflare in front | Volumetric attacks need upstream mitigation (CDN/provider); a single-node edge has finite capacity |
| 10 | **Hostname takeover / certificate abuse** | Per-host and per-alias DNS-TXT proof; unproven hosts are not certificate-eligible; `/internal/ask` rate-limited | Wildcard DNS-01 automation is restricted to platform admins |
| 11 | **Web attacks on the panel** (XSS, CSRF, clickjacking) | Nonce-strict `script-src`; CSRF synchronizer token; HSTS, `X-Frame-Options`; templ auto-escaping | CSP `style-src` still allows `unsafe-inline` |

## Review cadence

This document is revisited when a major feature lands (new role, new ingest
endpoint, new outbound integration, new secret type) and on every minor release.
Vulnerability reports follow the process in [../SECURITY.md](../SECURITY.md).
