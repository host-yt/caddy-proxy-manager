# Route Ownership, Aliases, Custom JSON and Caching

Per-route behaviour an operator has to understand before a route serves traffic:
who is allowed to claim a hostname, which extra hostnames get a certificate,
what may go into the raw Caddy handler chain, and when a response is allowed
into a shared cache.

Related: [MANUAL_CERTS.md](MANUAL_CERTS.md) for non-ACME certificates,
[SECURITY.md](SECURITY.md) for the control-plane threat model.

---

## 1. Domain ownership proof

A route serves a hostname only after that hostname is proven. The proof is a
DNS TXT record:

| | |
|---|---|
| Record name | `_hpg-verify.<domain>` |
| Record value | the route's verify token (`routes.verify_token`, 32 hex chars) |
| Match | exact, after trimming whitespace - not a substring match |
| Resolver | the zone's **authoritative nameservers**, queried directly; public bootstrap resolvers are used only if NS discovery fails |

Proof state lives in `routes.domain_verified`. Two rules follow from it:

- The node config builder emits a route only when
  `domain_verified = 1` **and** the status is `dns_ok`, `active` or
  `pending_ssl`. An unverified route produces no Caddy route at all, whatever
  status the row carries.
- Bulk **Retry SSL** on the hosts list skips any route that is not
  `ssl_enabled = 1 AND domain_verified = 1`; those routes count as failures in
  the result flash. `pending_ssl` is a serving status, so moving a route into it
  without proof would put an unowned hostname into the host matcher.

Editing the domain of a route resets `domain_verified`, the token, the status
and the issuance state in the same transaction as the edit.

---

## 2. Alias verification

A route may carry extra hostnames (`routes.aliases`). Since 1.4.4 each alias
carries **its own** proof; the parent route's proof does not cover it.

- Proven aliases are tracked in `routes.aliases_verified` (comma-joined subset
  of `routes.aliases`).
- Only proven aliases are emitted into the route's Caddy host matcher.
- Only proven aliases pass `/internal/ask`, so an unproven alias is not
  certificate-eligible - on-demand TLS returns 403 for it.

### What the owner has to publish

The **same token as the primary domain** (`routes.verify_token`), once per
alias:

```
_hpg-verify.shop.example.com.   TXT   "3f9c...<the route's token>"
_hpg-verify.www.example.com.    TXT   "3f9c...<the route's token>"
```

The token is per route, not per alias. The host edit form shows it in the
pending-alias banner.

### Where you see the state

**Admin → Hosts → edit.** Each alias renders as a chip labelled `proven`
(green) or `pending` (amber). When at least one alias is pending, a banner above
the list states how many aliases are not being served and prints the token to
publish.

### How an alias becomes proven

1. **The Verify button.** Running verification on the route checks the primary
   domain and every unproven alias in the same pass.
2. **The background sweep.** A leader-elected ticker runs
   `RecheckPendingAliases` every **10 minutes** over up to 500 non-disabled
   routes, re-querying only the aliases that are not yet proven. When the proven
   set changes it schedules a config push to the route's node, so the alias
   starts serving without any operator action.

Aliases that were removed from the route are dropped from `aliases_verified` on
the same pass.

### Proof on edit

- A **full platform admin** editing a host keeps the submitted alias list as
  proven.
- Any other principal (reseller-admin, client-scoped admin, client) gets the old
  proof intersected with the new list: a removed alias loses proof, a newly
  added alias starts unproven and must publish its TXT record.
- Adding any alias counts as a matcher change, so the collision/overlap checks
  re-run inside the update transaction.
- **Clone** does not copy `custom_config`, aliases or ownership proof.

---

## 3. Legacy alias claims (`/admin/legacy-aliases`)

### Why the page exists

Migration `00136` added `routes.aliases_verified` and backfilled it straight
from `routes.aliases` - every historical alias became "proven" with no TXT check
and no trusted provenance. Before 1.4.4 a scoped or reseller admin could persist
an alias without proving control of that hostname, so the backfill would have
promoted those claims into the host matcher and the on-demand-TLS allow-list.

Migration `00138` therefore parks every backfilled claim in
`route_alias_legacy_claims` (`route_id`, `aliases` snapshot, `status`,
`created_at`, `resolved_at`, `resolved_by`) and resets `aliases_verified` to
`NULL`.

**Consequence: every alias created before 1.4.4 stops serving on upgrade, and
stops being certificate-eligible.** Primary domains are unaffected. Expect
reports about additional domains going dark right after the upgrade.

### Recovery without the page

None needed if the owners already publish `_hpg-verify.<alias>`: the 10-minute
sweep proves the alias and re-pushes the node. A route whose aliases all become
proven closes its own claim with status `proven`.

### The page

**Security → Legacy aliases**, `super_admin` only (every handler calls a
super-admin guard and returns 403 otherwise). Reseller-admins and
client-scoped admins cannot reach it - it sits outside the reseller boundary
allow-list on purpose.

Columns: **Route** (links to the host edit page), **Client**, **Node**,
**Claimed aliases** (the frozen `00138` snapshot), **Not serving** (aliases the
route still lists that are in the snapshot but not currently proven),
**Status**. The header shows pending/resolved counts. Up to 5000 claims are
listed.

| Action | Method + path | Effect |
|---|---|---|
| Approve | `POST /admin/legacy-aliases/{id}/approve` | Restores proof for the aliases that are **both** in the frozen claim snapshot and still listed on the route; marks the claim `approved` with `resolved_at`/`resolved_by`; schedules a push to the route's node. An alias added after the migration can never be restored this way. |
| Dismiss | `POST /admin/legacy-aliases/{id}/dismiss` | Marks the claim `dismissed`. Touches nothing on the route - recovery is left to the TXT record. |
| Approve all | `POST /admin/legacy-aliases/approve-all` | Same as Approve, applied to every pending claim. Restores the pre-1.4.4 behaviour in one click. Only do this if you know your alias inventory is clean - approving is you vouching for hostnames that never carried DNS proof. |
| Export | `GET /admin/legacy-aliases/export.csv` | `hpg-legacy-aliases.csv`, columns `route_id, domain, client, node, status, claimed_aliases, not_serving, recorded_at`. |

Audit actions: `legacy_alias.approve`, `legacy_alias.approve_all`,
`legacy_alias.dismiss`.

---

## 4. Custom Caddy JSON: allow-list and quarantine

**Admin → Hosts → edit → Custom JSON** injects raw Caddy handler objects into a
route's handler chain. A raw handler runs on the node and can reach the node's
local Caddy admin API, so the content is restricted and the tab is
platform-admin only.

### Who may edit it

Only a **full platform admin** (unrestricted client scope). For a reseller-admin
or a client-scoped admin the tab is hidden, and a submitted change is rejected
with `custom Caddy handlers are platform-admin only`. Editing other fields of
the same route is unaffected.

### Allow-list

The value must be a JSON array of handler objects. Only these handlers are
accepted, with only these properties:

| Handler | Allowed properties |
|---|---|
| `headers` | `request`, `response` |
| `encode` | `encodings`, `prefer`, `minimum_length` |
| `rewrite` | `method`, `uri`, `strip_path_prefix`, `strip_path_suffix`, `uri_substring`, `path_regexp` |
| `vars` | any key; values must be scalars |
| `request_body` | `max_size`, `read_timeout`, `write_timeout` |

Per-handler schema checks on top of that:

- `headers`: request ops `add`/`set`/`delete`/`replace`; response ops add
  `require` and `deferred`. A `replace` entry takes only `search`,
  `search_regexp`, `replace`, and `search_regexp` must compile. `require` takes
  only `status_code` and `headers`.
- `encode`: encoder names limited to `gzip` and `zstd`, each with only a `level`
  key; `prefer` entries must be from the same set.
- `rewrite`: `uri_substring` entries take `find`/`replace`/`limit`;
  `path_regexp` entries take `find`/`replace`, with a non-empty, compilable
  `find`.
- `request_body`: all three values are **integers** (nanoseconds). A duration
  string such as `"30s"` is rejected.

### Rejections

- **Nested handler chains** at any depth: the keys `handler`, `handle`,
  `routes`, `handler_chain`, `error_routes`, `match`, `terminal`, `group` below
  a property are refused.
- **Placeholders that read the node**: any string *or map key* containing
  `{env.`, `{file.`, `{system.` or `{$` (case-insensitive) is refused. Header
  values expand placeholders around a body the tenant's own upstream controls,
  which would leak node secrets.
- Nesting deeper than 8 levels, and payloads over 16 KiB.

### Not allowed, and why

| Handler | Reason |
|---|---|
| `reverse_proxy` | A route pointed at `127.0.0.1:2019` turns a public hostname into a path to the node's unauthenticated Caddy admin API - full takeover of that node and every tenant on it. |
| `templates` | Caddy's template FuncMap ships `env`, `readFile`, `httpInclude` and `placeholder` with no sandbox. |
| `rate_limit` | Its zones contain `match` blocks, which the nesting rule refuses. Use the route's native rate-limit fields instead. |

### Quarantine

The stored chain is validated on write **and again at emission**. A route whose
stored chain no longer passes is not served unguarded: it is emitted as a
**terminal** route whose only handler is a `static_response`:

```
HTTP/1.1 503 Service Unavailable
Cache-Control: no-store
Retry-After: 60
X-Hpg-Quarantine: custom-handlers
Content-Type: text/plain; charset=utf-8

Service unavailable: this route is quarantined because its custom handler chain
failed validation. A platform administrator must review it.
```

The route being terminal matters: no wildcard or catch-all route further down
can pick up the hostname instead.

The reason is deliberately not in the response body. It is in the audit log as
`route.custom_handlers.quarantined` (entity `route`, meta `domain` and
`reason`), and in the panel log as `route quarantined: custom handler chain
rejected`.

**Recovery:** open the host and save it. The stored chain is re-sanitized on
every save, so a non-conforming chain is dropped rather than carried forward,
and the route goes back to serving normally on the next push. To keep custom
handlers, rewrite the chain so it passes the allow-list.

---

## 5. Shared caching is opt-in

**Admin → Hosts → edit → "Content is public (share across all visitors)"**
(`routes.cache_public`, migration `00133`, default `0`).

Existing routes keep serving after an upgrade, but nothing is stored in a
shared/CDN cache until you tick this box. The old default advertised
authenticated and audience-restricted responses as publicly cacheable.

Tick it only when every visitor may see the identical response.

### What gets emitted

| Route | `Cache-Control` | Souin cache handler |
|---|---|---|
| Auth-gated (see below) | `private, no-store` | never |
| Cache on, `cache_public` off | `private, max-age=<ttl>` | no |
| Cache on, `cache_public` on, audience-restricted | `private, max-age=<ttl>` | yes, if the cache module is available |
| Cache on, `cache_public` on, unrestricted | `public, max-age=<ttl>` | yes, if the cache module is available |

TTL defaults to 60 s when unset.

**Auth-gated** always means `private, no-store`, regardless of the checkbox:

- SSO forward-auth configured,
- basic auth (single user or user list),
- portal protection,
- mTLS / require-client-certificate,
- an external HTTPS upstream with a proxy secret,
- a custom handler chain that is not itself inside the safe allow-list.

**Audience-restricted** downgrades `public` to `private` but still allows the
cache handler to run:

- block-all access mode, or a non-empty IP deny list,
- geo mode `allow` or `deny`, or non-empty geo block CIDRs.

### Credentialled requests

Independent of all of the above, the emitted chain is a subroute with two
branches. A request carrying a `Cookie` **or** an `Authorization` header always
takes the `private, no-store` branch and never touches the shared cache.

### `Set-Cookie` stripping

`Set-Cookie` is deleted (deferred response header delete) **only** on responses
actually emitted as publicly cacheable - `cache_public` on and not
audience-restricted, on the non-credentialled branch. A route serving
`private` responses keeps its cookies.

### Ordering

`rate_limit` is emitted **before** the cache handler. A cache hit short-circuits
the handler chain, so a rate limit placed after the cache would never see repeat
requests.
