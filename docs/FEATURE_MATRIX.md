# Feature Matrix

Comparison of HPG with common alternatives.

| Feature | HPG | Caddy Proxy Manager | CaddyUI | Notes |
|---------|-----|--------------------|---------|----|
| Admin panel | yes | yes | yes | All three have a web UI |
| Multi-tenant clients | yes | no | no | HPG: client role with quota-isolated services |
| Plans / quotas | yes | no | no | Max domains, ports, RPM per plan |
| WireGuard VPN | yes | no | no | Customer tunnels + manager mesh + WG-over-WSS |
| L4 TCP/UDP streams | yes | no | no | Requires caddy-l4 module |
| WAF | yes | no | no | Requires WAF Caddy module; per-route toggle |
| GeoIP analytics | yes | no | no | Country-level; world map view |
| AI assistant | yes | no | no | Scoped to role; per-user rate limit |
| Analytics dashboard | yes | partial | no | HPG: Prometheus-backed charts + KPI cards |
| mTLS per route | yes | no | no | Requires mTLS Caddy module |
| HTTP cache per route | yes | no | no | Souin module; per-route toggle |
| Audit log | yes | no | no | All write ops logged with actor + IP |
| REST API | yes | no | no | Bearer key auth; per-key RPM cap |
| SSO forward-auth | yes | no | no | Per-route; any forward-auth provider |
| Basic auth per route | yes | yes | yes | |
| TOTP 2FA | yes | no | no | TOTP + email OTP + SMS OTP + passkey |
| WebAuthn / passkey | yes | no | no | |
| OIDC login | yes | no | no | |
| Multi-node fleet | yes | no | no | Placement heuristics, node groups, drain |
| DNS-01 wildcard ACME | yes | yes | no | HPG: via caddy-dns providers |
| On-demand TLS | yes | yes | no | HPG: `/internal/ask` gate with DB check |
| Backup / restore | yes | no | no | S3/SFTP/FTP; restore drill CLI |
| Install wizard | yes | yes | no | |
| Docker Compose deploy | yes | yes | partial | HPG: single compose for full stack |
| Self-hostable | yes | yes | yes | All three are self-hosted |
| Open source | yes | yes | yes | |
