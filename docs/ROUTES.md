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

---

## 6. Importing from Nginx Proxy Manager

`/admin/tools/npm-import` takes an NPM **Full Backup** JSON export.

**Preview first.** The Preview button runs the whole import in dry-run mode:
it screens forward hosts, checks which domains this panel already serves, and
reports what a real import would create - without writing anything. The real
import then does the same work for real.

Every entry in the backup ends up in the report under one of three actions:

| Action | Meaning |
|--------|---------|
| `imported` | A route was created (dry run: would be created). |
| `skipped` | Nothing to do: disabled in NPM, no forward host, a domain this panel already serves, or a forward host rejected by SSRF screening. |
| `manual` | Recognised, but the panel has no automatic equivalent. Carry it over yourself. |

Imported automatically:

- **proxy hosts** - one route per domain, forwarding scheme/host/port, `ssl_forced`
  mapped to SSL + force-HTTPS. One service per distinct backend, tagged `npm-import`.
- **redirection hosts** - as redirect routes, keeping the NPM status code
  (301/302/307/308; anything else becomes 301). NPM's `auto` scheme becomes
  `https`, because the panel emits a fixed `Location`.

Reported as `manual`, never guessed at:

- **streams** - recreate as L4 streams (needs the caddy-l4 module).
- **access lists** - recreate as basic auth, an IP allow-list, or the access portal.
- **custom certificates** - `letsencrypt` ones need nothing (the panel issues its
  own); anything else has to be imported under Manual certs.
- **404 hosts** - recreate as a route in maintenance mode, or a redirect.
- **location rules**, **`advanced_config`** (raw nginx), NPM caching,
  block-common-exploits, HSTS, and a redirect's `preserve_path` - each is
  listed against the host it belongs to, with the nearest panel equivalent.

A forward host that resolves to loopback, link-local or a cloud metadata
address is refused, in the dry run and the real import alike.

---

## 7. Backend address pinning

The panel resolves and screens a route's backend hostname when it builds the
Caddy configuration, then emits the resolved address as the dial target. The
original hostname is kept as `transport.tls.server_name`, so an HTTPS backend
still verifies the certificate against the name you configured, not the
address that was dialed.

**DNS round-robin across a single backend name no longer spreads traffic.**
When the name resolves to more than one address, the panel picks one - the
lexically lowest - instead of handing every answer to Caddy. This also keeps
repeated pushes byte-identical, so they don't trigger a drift resync. Add
several upstreams to the route instead of relying on multiple DNS answers to
spread load.

**A changed address is picked up on the next push:** immediately when the
route itself is saved, otherwise within the drift sweep (every 5 minutes).

**What gets pinned.** A backend name is resolved and pinned only when the
panel is the one dialing it and a single address will do. It is screened
against the deny set but kept as a name - not resolved or pinned - when:

- the route has the "backend is resolved on the node" switch set (below),
- the route is bound to a tunnel peer,
- it's an operator-allowlisted External origin,
- the route uses a custom backend resolver,
- it's an HTTPS pool whose upstreams span more than one hostname - one TLS
  connection carries one SNI, so pinning any of them would break the rest.

**Pins live in panel memory, not the database.** After a panel restart the
pinned-address cache starts empty. If a route's backend name still cannot be
resolved by the time the panel next builds its config, that route is dropped
from the push entirely - not kept on its last known address - and the drop is
written to the audit log (`route.blocked_target`). The route starts being
served again once the name resolves, or once the "backend is resolved on the
node" switch is set on it.

---

## 8. "Backend is resolved on the node" switch

**Admin → Hosts → add/edit → "Backend is resolved on the node"**
(`routes.backend_resolve_node_side`, migration `00146`, default off).

Saving a proxy backend whose hostname the panel cannot resolve normally fails,
naming this switch in the error. Tick it for a name only the node can look
up - a container name on the node's own network, or a tunnel peer name - and
the save succeeds without the panel needing to resolve it.

A route with the switch set is not resolved or pinned by the panel (see
above): the hostname is only checked against the deny set and handed to the
node as-is, and the node dials whatever the name resolves to on its side.

Existing tunnel-bound routes were backfilled to this switch by the same
migration, so an upgrade does not take them down.

---

## 9. SSO strict mode

**Admin → Hosts → edit → "Single sign-on (forward-auth)" → "Strict mode"**
(`routes.sso_strict_mode`).

**Strict** gates every request to the route, regardless of method or path: a
request that the identity provider does not answer with a 2xx gets a `401`
JSON response from the panel, not the provider's own login redirect.

**Permissive (document-only)** gates GET/HEAD page loads only, and skips
common static-asset paths and extensions. Every other request - any other
method, and anything matching those skipped paths - reaches the backend
without going through the SSO gate at all. An unauthenticated page load gets
the identity provider's own response (typically a redirect to its login page)
passed back to the browser, instead of a `401`.

Permissive mode remains available as a per-route, deliberate opt-out. Turning
it on for a route is written to the audit log
(`host.sso_permissive_enabled`).

Migration `00147` moves every existing SSO-enabled route that was still on
permissive to strict. Run `server doctor` with the new binary **before**
starting it: its `routes: SSO strict mode` check lists every route the
migration is about to change (the same check, run after the upgrade, instead
lists routes left permissive on purpose). An application behind an affected
route that relied on an unauthenticated non-GET/HEAD request, or on a request
under one of the skipped static paths, starts getting a `401` from the panel
instead of reaching the backend.

---

## 10. Built-in access portal

**Admin → Hosts → edit → Portal** (`routes.portal_protect`,
`route_access_grants`, `routes.portal_public_paths` since migration `00148`).

A self-hosted login gate, an alternative to external SSO: protected GET/HEAD
page loads are checked against the panel's own verifier and an
unauthenticated visitor is sent to a login form on the same host. Members
sign in with their normal email + password; groups and members are managed
under **Security → Access groups**.

### Protection intent alone does not gate the route

Turning "Protect with built-in portal" on has no serving effect by itself -
the gate only takes effect once at least one access group is **granted**
access to the route. An empty grant list is a misconfiguration, not "no
gate": the route is emitted as a terminal `503`

```
Service unavailable: access portal protection is on but nobody has been granted access.
```

instead of being served publicly and instead of being silently skipped. The
distinction matters for anyone reasoning from the checkbox alone: enabling
protection and forgetting to grant a group takes the route down, it does not
leave it open.

### How a request is matched to a route

The verifier does not trust anything the request claims about itself; it
looks the request up the same way the node does when it builds config
(`RouteForRequest`):

- **Host**: the primary domain, or any alias whose ownership is proven -
  the same set described in [Alias verification](#2-alias-verification).
- **Path**: the longest `path_prefix` under that host the request path
  starts with (a route with no prefix is the host's catch-all).
- Only routes with `domain_verified = 1` and status `dns_ok`, `active` or
  `pending_ssl` are candidates - the same set the node actually serves.
- Two routes on the host tying on prefix length is an **ambiguous** match,
  and an ambiguous match is denied. There is no "probably right" route for
  an access check.

Both the host and the path used for this lookup come from the gate config
the panel itself wrote into the route's Caddy handler chain (forwarded
`Host` and `X-Forwarded-Uri`); a check missing either is refused outright.

### Public paths are explicit and opt-in

`routes.portal_public_paths` (Portal tab → **"Public paths (bypass the
portal)"**) is a list of Caddy path matchers, one glob per line (for
example `/assets/*`, `*.js`) that a GET/HEAD request may reach without a
portal session. **Empty means no exceptions**: every request to a protected
route, whatever its path, hits the verifier. Any method other than GET/HEAD
is always gated, even under a listed public path.

This replaces an older implicit bypass that treated any path merely
*looking* like a static asset as public. Migration `00148` removes that
inference. On upgrade, a protected route whose assets used to load
anonymously starts sending every one of those requests to the verifier -
list the paths explicitly first, or an SPA hard-refresh stampedes it.

### Sessions

A portal session is minted with the account's authorization epoch
(`users.auth_epoch`) and re-checked on every verify, the same mechanism
admin and client sessions use - see
[Authorization epoch](SECURITY.md#authorization-epoch). Disabling the
account or any change that bumps the epoch drops the portal session on its
very next request, same as it would an admin session.

---

## 11. Route publish state

The hosts list shows two independent status lines per route: **health**
(the DNS/SSL pipeline: `pending DNS`, `DNS ok`, `pending SSL`, `active`,
`failed`, `disabled`) and **publish state** - the outcome of the last time
this route was actually compiled into a node's Caddy config. The two can
disagree, and when they do the publish state is the one describing what is
really being served:

| Publish state | Meaning |
|---|---|
| `published N/M` | Compiled cleanly and the last `/load` on all M serving nodes succeeded. |
| `pending N/M` | Compiled cleanly; a push to at least one node is scheduled but has not run yet. |
| `push failed N/M` | Compiled cleanly, but at least one node refused or could not be reached on its last `/load`; that node still serves its previous config. |
| `unconfirmed N/M` | Compiled cleanly; at least one node has no recorded `/load` since the upgrade that added this tracking. |
| `compiled` | Compiled cleanly, but no enabled node serves the route. |
| `quarantined` | The stored config no longer passes validation - a custom Caddy JSON chain (see above) or a tenant string using a placeholder outside the [allow-list](#12-tenant-placeholder-allow-list). Served as a terminal `503`. |
| `rejected` | An auth gate the operator turned on cannot be emitted - most often a portal with no group granted, or an mTLS route whose CA cannot be read. Served as a terminal `503`. |
| `target rejected` | A backend or extra upstream failed the infrastructure/SSRF screen at emission time; that target is dropped. |
| `not emitted` | An external upstream host is not allow-listed, or its proxy secret cannot be decrypted. The route produces no Caddy route at all. |
| `unchecked` | No compile outcome has been recorded yet - a new install, or a route not yet re-published since the upgrade that added this tracking. Not the same as "fine". |

N counts the serving nodes (anchor node plus fan-out peers) whose last `/load`
holds the current config; the pill shows the worst node. Hover it for each
node's state and its last push error. Pending is tracked by the panel process
that schedules the push. Hover the other pills for the stored reason. A route reading `active` health next
to a `quarantined` or `rejected` publish state is not a bug to chase down -
both are accurate at once, and the publish state is the one to act on.

---

## 12. Tenant placeholder allow-list

Caddy expands `{...}` placeholders wherever they appear in emitted config,
including in a handful of fields a tenant controls directly. Because these
values can land in a response header, a redirect target or a rewrite target
that Caddy's replacer processes, only one namespace is permitted in them:
**`http.request.*`** - derived from the request the node is already serving
for that tenant. Every other namespace (`{env.*}`, `{file.*}`, `{system.*}`,
`{$...}`) is refused.

The allow-list applies to:

- **Redirect URL** (`routes.redirect_url`)
- The geo-block redirect URL
- **Upstream host header** and the upstream TLS SNI override
- Custom response headers - both the header name and its value
- Each **location rule**'s redirect URL and rewrite target - the UI's own
  placeholder example uses this pattern:
  `https://new.example.com{http.request.uri}`

The rate-limit key is exempt from the allow-list by design (the UI offers
building a custom one from request data); only the node-state namespaces
above are refused there.

### Refused at save, or held back at publish

**Redirect URL** is checked when the route is saved (UI and
`PATCH /api/v1/routes/{id}` alike) and the save is rejected outright if it
carries a disallowed placeholder. The other allow-listed fields above are
not blocked at save time - a bad value in one of them is only caught the
next time the route is published, and a route already holding one is **held
back**, not published with the value dropped or neutralized. It shows
publish state `quarantined` on the hosts list (see above); the panel log
records which field was the cause. Re-save the field with a permitted value
to clear it.

---

## 13. Suspended services and route state

Suspending a service (**Admin → Services**, or the reseller/API equivalent)
stops its routes from serving, but it never deletes a route's definition and
never touches `custom_config`, aliases or any other field - only
`routes.status` and `routes.disabled_reason`.

- **Suspend** flips every route in a serving status (`active`, `dns_ok`,
  `pending_ssl`) to `disabled`, and stamps `disabled_reason` with the cause
  (service suspended, or service terminated).
- **Resume** re-enables only the routes that reason names. A route an
  operator disabled by hand before the suspend (`disabled_reason` empty)
  stays disabled after resume - resume restores what suspend took away, it
  is not a bulk "turn everything back on".
- **Terminate** is suspend's terminal form: routes stop serving the same
  way, but resume can never bring them back. The route rows still survive
  for inspection or export.

The host edit page and the hosts list read the same `routes.status`/
`disabled_reason` an operator would set by hand, so a route disabled by a
suspended service looks like any other disabled route there - the audit log
and the service's own status page are what say *why*.
