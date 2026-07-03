# Security policy

## Supported versions

This is a young project. Only the `main` branch is currently
maintained.

## Reporting a vulnerability

**Do not open a public GitHub issue.** Email the maintainer
(address in repository owner profile) or, if the repository is on a
forge that supports it, open a private security advisory.

Please include:

- Affected endpoint or code path.
- Reproduction steps (or a proof-of-concept).
- Your suggested fix, if you have one.
- Whether you'd like credit in the changelog.

Expect an initial response within 72 hours.

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
