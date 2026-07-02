# Roadmap

## Shipped (v0.1)

Core platform:
- Install wizard with step-by-step guided setup
- Multi-tenant RBAC (super_admin / admin / client / support)
- NPM-style flat host management (admin)
- Client portal with service and route management
- Argon2id password auth + TOTP + email OTP + SMS OTP + WebAuthn/passkey
- OIDC/OAuth2 login (Google, etc.)
- API key auth with per-key RPM cap
- SSO impersonation + jump tokens
- Redis-backed sessions, CSRF, brute-force protection

Caddy integration:
- Full and incremental config push to Caddy Admin API
- On-demand TLS via `/internal/ask`
- Route features: TLS, redirect, static response, WebSocket gate, basic auth, SSO forward-auth, ACL, cache, gzip/zstd, rate limit, force-HTTPS, custom headers
- DNS-01 wildcard ACME via caddy-dns providers (Cloudflare, Route53, Gandi, Hetzner, Porkbun, Namecheap, GoDaddy, Vultr)
- Node fleet management with placement heuristics and health polling
- Drift reconciler and leader election for HA setups

WireGuard:
- Manager mesh WireGuard (node-to-manager)
- Customer WireGuard tunnels with auto IP allocation
- WireGuard-over-WebSocket (wstunnel) for firewalled networks
- Node agent binary for remote Caddy nodes

Advanced modules (require non-stock Caddy build):
- L4 TCP/UDP streams (caddy-l4)
- WAF with event log
- mTLS per route
- Souin HTTP cache per route
- GeoIP analytics (country-level, GeoLite2-Country)

Analytics and monitoring:
- Prometheus-backed KPI dashboard (request rate, error rate, latency)
- Analytics v2 with time-series charts
- World map (country-level choropleth, admin + client)
- Top countries per route

AI assistant:
- Scoped chat bubble (admin: all data; client: own data only)
- Role-filtered tool set
- Per-user rate limiting

Operations:
- DB backup scheduler (S3/SFTP/FTP)
- Restore drill CLI (`cmd/restore`)
- `APP_SECRET` rotation CLI (`cmd/rotate-secret`)
- Audit log
- Install profiles (homelab / smallteam / advanced / provider)

---

## Beta

- **Automatic failover** - detect unhealthy node, reroute affected routes to a standby node automatically
- **Caddy capability probe** - detect at startup which non-stock modules are loaded; auto-set `*_AVAILABLE` flags without manual env config

---

## Shipped (v1.3)

- **Reseller tier** - reseller-admins with own clients, reseller-scoped plans, white-label client portal + status page, suspend/resume (fails closed)
- **Terraform provider** (`terraform-provider-hpg`) - manage nodes, node pools, plans, clients, services and routes via Terraform/OpenTofu; multi-tenant key scope
- **Lite deployment** - `docker-compose.lite.yml` on stock Caddy (edge modules disabled) for installs that do not need WAF/GeoIP/L4

---

## Planned

- **Automatic failover** hardening and richer node-health signals
