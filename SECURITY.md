# Security policy

## Supported versions

Only the latest minor release line gets security fixes: currently **1.8.x**
(plus `main`). Upgrade to the newest patch release before reporting.

## Reporting a vulnerability

**Do not open a public issue or pull request, and do not post details in
Discussions.** Use GitHub private vulnerability reporting:

<https://github.com/host-yt/caddy-proxy-manager/security/advisories/new>

Please include:

- Affected endpoint or code path.
- Reproduction steps (or a proof-of-concept).
- Your suggested fix, if you have one.
- Whether you'd like credit in the advisory.

## Response targets

| Step | Target |
|------|--------|
| Acknowledgement | within 3 days |
| Fix for high severity | within 14 days |
| Fix for medium severity | within 60 days |

Low severity is fixed in a regular release. Targets are best effort from a
single maintainer; you will be told if one slips.

## Disclosure

Coordinated disclosure: details stay private until a fix is released. After
that the issue is published as a GitHub Security Advisory (with a CVE where
applicable) and credited in the changelog.

## Hardening checklist for operators

This applies to anyone running the panel in production. See also
[`docs/SECURITY.md`](docs/SECURITY.md) (threat model).

### Network

- Bind the app's `8080` to `127.0.0.1` and front it with a TLS-
  terminating reverse proxy (the bundled Caddy works fine).
- The Caddy admin port `:2019` MUST NOT be reachable from the public
  internet. The bundled compose keeps it on the internal Docker
  network or on the WireGuard interface only.
- UDP `51820` (WireGuard) on the manager: open to each node's public
  IP, closed to everyone else.
- On a node: open `80`, `443` (TCP + UDP for HTTP/3), and the
  WireGuard port.

### Secrets

- `APP_SECRET` must be at least 32 bytes of entropy
  (`openssl rand -hex 32`). Rotating it invalidates encrypted
  settings - keep a backup before rotation.
- Don't commit `.env` to git. The `.gitignore` excludes it; keep it
  that way.
- The DB user the panel runs as needs `CREATE`, `ALTER`, `DROP` only
  during migration runs. Production deployments may run migrations
  with a privileged user and then strip the panel user back to DML.

### Accounts

- Enable 2FA on every super-admin and admin account.
- Disable the OIDC `auto_provision` flag in environments where you
  don't want anyone who can authenticate on the IdP to land in the
  panel.
- Rotate API keys quarterly. Revocation is instant - old keys stop
  authenticating immediately.

### Cloudflare

- Only flip `Trust CF-Connecting-IP` when the app actually sits behind
  Cloudflare. Otherwise an attacker can spoof their IP for rate-limit
  evasion and audit logs.

### Upgrades

- Migrations run automatically on boot (goose, idempotent). Always
  back up the database before upgrading.
- Pin image tags in production; review the changelog before bumping.

## Known limitations

- The CSP still allows `unsafe-inline` on `style-src` (inline styles
  in templates). `script-src` is already nonce-strict. Dropping
  `unsafe-inline` from styles is pending the inline-style-to-class
  migration; until then, XSS via injected `<style>`/style attributes
  is not blocked by CSP alone.
