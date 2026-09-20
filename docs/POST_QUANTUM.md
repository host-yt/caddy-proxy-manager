# Post-Quantum Readiness

## Overview

The threat this addresses is **harvest-now-decrypt-later** (HNDL): an attacker
records encrypted traffic today and decrypts it once a cryptographically
relevant quantum computer exists. Only *key exchange* and *long-lived
confidentiality* matter for HNDL. Signatures do not: a signature forged in
2035 cannot retroactively authenticate a 2026 handshake that already happened.

So the work splits cleanly:

- **Key exchange** - hybrid ML-KEM (X25519MLKEM768) everywhere TLS is spoken,
  and WireGuard preshared keys on both WireGuard planes. Done, described below.
- **Signatures** (certificates, ACME account keys, OIDC tokens, image
  signatures) - blocked upstream, and not an HNDL risk. See
  [Not covered](#not-covered-upstream-blocked).

Most of this is on by default and needs no configuration. Two things are
opt-in: mesh preshared keys on nodes that joined before the feature existed,
and per-host PQ-only enforcement.

## What is covered

| Layer | State | How |
|---|---|---|
| TLS to visitors (edge Caddy 2.11.4) | hybrid, on by default | Caddy's default curve list is `[X25519MLKEM768, X25519, P256]`; the panel never emits `curves` unless a host is PQ-only |
| TLS from the panel (Go 1.26) | hybrid, on by default | Go 1.24+ offers X25519MLKEM768 first; no `CurvePreferences` anywhere in non-test code (CI-guarded) |
| Panel -> node mesh (WireGuard) | preshared key | automatic on new joins, one-time rekey script for older nodes |
| Customer tunnels (WireGuard) | per-peer preshared key | automatic once the node's `node-agent` reports support |
| WSS transport (wstunnel 11.0.0) | hybrid, on by default | its rustls/aws-lc-rs build already offers X25519MLKEM768 on the outer WSS layer; the inner WireGuard adds the PSK |
| Secrets at rest, passwords, tokens | already quantum-resistant | AES-256-GCM + HKDF-SHA256, Argon2id, HMAC-SHA256 - symmetric primitives lose at most half their bit strength |
| Certificates and other signatures | not available | see [Not covered](#not-covered-upstream-blocked) |

A read-only summary of the same table, filled in with this installation's real
numbers, lives at **Admin -> Settings -> Post-quantum**.

## Why WireGuard needs help

WireGuard's handshake is Noise IK over Curve25519 - classical ECDH, with no
hybrid mode in the protocol. Its escape hatch is `PresharedKey`: 32 symmetric
bytes mixed into every handshake. An attacker who records the session and later
breaks X25519 still cannot derive the session keys without those bytes, which
never appear on the wire.

There are two separate WireGuard planes in HPG, and they are configured
independently:

- **Mesh** (`wg0`): panel <-> node. Carries Caddy config pushes, which include
  manual-certificate private keys - which is exactly why HNDL matters here.
- **Customer tunnel** (`wg-tun0`): customer device <-> node, managed through
  `customer_wg_peer` and driven by `node-agent`.

---

## Mesh preshared keys (panel <-> node)

### New nodes

A node joining with the current `node-join.sh` gets a PSK automatically. The
join request declares `"supports_psk": true`; the join response carries
`wireguard.peer.preshared_key`, which the script validates and appends to
`/etc/wireguard/wg0.conf`. The panel stores it encrypted in
`caddy_nodes.wg_psk_enc` (envelope purpose `wg`) and renders it into its own
`wg0.conf` in the same breath, so both sides have the key from the first
handshake.

The capability flag matters: a node bootstrapped from an **older cached
`node-join.sh`** omits `supports_psk`, the panel then stores no key, and that
node keeps working exactly as before. Nothing is ever handed a key it will
silently drop.

### Existing nodes: the rekey flow

Nodes that joined before this release have no PSK. The node detail page
(**Admin -> Caddy nodes -> <node> -> Mesh WireGuard PSK**) shows the state and
drives the rekey:

1. **Enable PSK** (or **Rotate PSK** if one is already active). This *stages* a
   key in `wg_psk_pending_enc` and mints a 64-hex, 30-minute token. The
   currently active key stays in use - nothing changes on the wire yet.
2. The page prints the command to run **on the node**:

   ```bash
   curl -fsSL https://panel.example.com/install/node-psk.sh | sudo bash -s -- \
     --panel https://panel.example.com \
     --token <64-hex token>
   ```

   The script requires `bash`, `curl`, `jq`, `wg`, `wg-quick` and root, and it
   needs the panel reachable over **public HTTPS** - the same requirement as
   `node-join.sh`.
3. The script fetches the staged key (`GET /api/node/psk`, token in an
   `Authorization: Bearer` header), backs up `wg0.conf`, rewrites **only** the
   `[Peer]` block whose `PublicKey` matches the manager's - the fetch response
   carries `peer_public_key` for exactly this reason, so a hand-added peer on
   the same interface is left untouched - and applies it with `wg syncconf`.
4. It then calls `POST /api/node/psk/confirm` with the same bearer token. The
   panel promotes the staged key to active, re-renders its own `wg0.conf`,
   clears the pending marker **last** (see below), and answers `204`.
5. The script waits up to 130 s for a fresh handshake and reports the result.
   A missing handshake is a warning, not a failure - by then both sides are
   already committed.

The panel never activates a key before the node confirms it, so the two sides
are never more than one handshake apart.

### Idempotence and retries

Confirm is **idempotent for the lifetime of the token**: the token columns are
not cleared on promotion, and a repeated confirm returns `204` again. That is
deliberate. If the response to the first confirm were lost, a one-shot token
would make the retry fail, the script would roll the node back, and the mesh
would end up split across two keys with no way to recover.

**`wg_psk_pending_enc` marks "the panel has not applied this yet", not "not
promoted yet".** Promotion copies pending into `wg_psk_enc` and *leaves pending
in place*; it is cleared only once the panel's own `wg0.conf` is on disk. So a
NULL pending means **applied here**, and that is the only state in which a
confirm short-circuits to `204` without doing any work.

That distinction is what makes a concurrent or retried confirm safe. The row is
taken with `SELECT ... FOR UPDATE`, so a second confirm arriving while the first
is still rendering blocks on the row lock and then finds pending still set - it
repeats the same idempotent promote-and-render rather than reporting success.
Before this, the retry read "pending is NULL, therefore done" and answered `204`
while the first call could still fail its render and compensate back to the
*old* key: the node would then hold the new key against a panel that had
abandoned it, which is precisely the split the token TTL exists to prevent.

So the script only rolls back on a *definite* `4xx`. On a `5xx`, a timeout or no
answer at all it retries (5 attempts with backoff) and, if the outcome is still
unknown, **keeps the new key** and tells you to re-run the same command.
Re-running it is always safe.

Should the panel fail to render its own `wg0.conf` after promoting, it
compensates - puts the previous active key back (pending and the token were
never cleared, so restoring the old active key is the whole rollback),
re-extends the token, and answers `500` so the script rolls the node back too.
If even that fails it logs `node.psk.compensate.failed` in the audit log; that
case needs **Clear PSK**.

The one remaining crack is harmless: if the render succeeds but the final
"clear pending" write fails, the key is live on both sides anyway and the next
confirm re-promotes the same key, re-renders, and clears the marker. Until then
the node still reads as `PSK` active - the readiness card reports active in
preference to pending.

### Timing: what a mismatch actually breaks

WireGuard keeps an established session alive until the next handshake
(`REKEY_AFTER_TIME` is 120 s). A PSK mismatch is therefore **not instant**: the
mesh keeps working for up to ~2 minutes and then stops handshaking.

What that costs:

- The panel can no longer reach `http://<wg-ip>:2019`, so **Caddy config pushes
  and resyncs to that node fail** and the node goes offline in the panel.
- **Visitor traffic is unaffected.** The node keeps serving whatever config it
  already has; the mesh is a control plane, not a data path.

### Multi-replica: the 60 s mesh reconcile

Every replica re-renders `wg0.conf` from the database **every 60 s**, and this
loop is deliberately *not* leader-gated - unlike almost every other background
job here. The file is replica-local and each replica feeds its own WireGuard
sidecar, so a mesh mutation handled by one replica (a node join, a PSK rekey
confirm) would otherwise never reach the other replicas' sidecars, and half the
panel would stop being able to talk to the node.

The cadence is chosen against WireGuard's `REKEY_AFTER_TIME` of 120 s: a key
confirmed on replica A lands in replica B's config well inside the window in
which B's existing session is still valid, so the change costs no handshake.

Two things keep the loop cheap:

- `Write` compares the rendered body against what is on disk, ignoring the
  generated-at header line, and returns without touching the file when they
  match. The sidecar polls mtime and runs `wg syncconf` on every change, so
  before this an unrelated admin action that happened to re-render the config
  poked the interface for nothing.
- With WireGuard mode off in Settings the reconcile is a silent no-op; it does
  not log.

### Clear PSK (emergency exit)

**Clear PSK** drops `wg_psk_enc`, the pending key and the token on the *panel
side only*. The node still has its `PresharedKey` line, so the mesh stays down
until you remove it there too:

```bash
sed -i '/^PresharedKey/d' /etc/wireguard/wg0.conf
wg syncconf wg0 <(wg-quick strip wg0)
```

The flash message on the node page repeats that command verbatim - but **only
when the panel's own config really changed**. If `wg0.conf` cannot be written,
the previous state (active key, pending key, token hash and token) is restored,
the page says that nothing was cleared, and the node-side command is
deliberately **not** printed: stripping the key on the node while the panel
still holds it is exactly what takes the mesh down. Retry, and read the panel
log if it keeps failing.

If that restore also fails, the database and the panel's config disagree about
this node - logged at ERROR and audited as `node.psk.clear.failed`.

### Endpoints and audit trail

| Path | Auth | Purpose |
|---|---|---|
| `GET /install/node-psk.sh` | none (non-secret script) | the rekey script |
| `GET /api/node/psk` | `Authorization: Bearer <token>` | returns `{"psk", "peer_public_key"}`; does **not** consume the token |
| `POST /api/node/psk/confirm` | `Authorization: Bearer <token>` | promotes the staged key, re-renders the panel config, clears the pending marker last; `204` |

Both API endpoints sit outside the session middleware - the token hash in
`caddy_nodes.wg_psk_token_hash` is the entire authentication. Every failure
answers `404`, so a caller cannot tell a bad token from an expired one, and
calls are rate-limited per source IP (30/min, Redis-backed with an in-process
fallback).

Audit actions: `node.psk.enable`, `node.psk.rotate`, `node.psk.confirm`,
`node.psk.clear`, `node.psk.clear.failed`, `node.psk.ratelimited`,
`node.psk.fetch.denied`, `node.psk.confirm.denied`,
`node.psk.compensate.failed`.

---

## Customer tunnel preshared keys

Per-peer PSKs on `wg-tun0` are automatic, but gated on both sides because a
`PresharedKey` line an agent does not understand makes `wg syncconf` reject the
**whole** config - every peer on that node would drop.

**The gate has two halves:**

- A **peer** is only given a PSK when *every* node in its group reports support.
  For an HA peer group that is all of its nodes: the customer gets one `.conf`
  with one `[Peer]` block per node, so a PSK on some and not others would leave
  it half-broken.
- A **node** only receives `preshared_key` in its `GET /api/node/wg/peers` pull
  when *that* node itself supports them - and the pull negotiates that on the
  request itself, see below.

`node-agent` re-asserts `node.psk_supported` on every `POST /api/node/wg/stats`
report (roughly every 30 s). It is a plain boolean and **an absent field means
"not supported"** - so rolling an agent back to a pre-PSK image clears the flag
on its own within one report cycle, rather than leaving a stale `1` behind.

### The pull negotiates capability (409 Conflict)

`node-agent` sends `X-HPG-Agent-PSK: 1` on every `GET /api/node/wg/peers`. The
**header**, not the stored flag, decides how that request is answered: the flag
describes whichever agent build reported last, while the header comes from the
build that is about to apply the answer.

An agent that does not send it is recorded as PSK-incapable
(`caddy_nodes.agent_psk` goes to 0 on that same request, with the
`node.psk_capability_lost` audit entry on the 1 -> 0 edge), and then:

| That node's peers | Response |
|---|---|
| none holds a PSK | `200` with the peer set, PSKs omitted as before |
| one or more hold a PSK | **`409 Conflict`**, no peer set at all |

The 409 is the safe answer, not the timid one. `wg syncconf` replaces the peer
set **atomically**, so an agent that cannot express `PresharedKey` would apply
the PSK-less set wholesale and drop every one of those tunnels at once. Its
*currently running* config still carries them and still works - so refusing to
answer is what keeps those customers up, while answering is what takes them
down. The agent logs the 409 body and changes nothing.

**Getting out of it**, two operator moves:

- upgrade `node-agent` on that node - the intended fix; or
- rotate the affected peers' keys, which drops their PSKs (see [Rotation
  degrades rather than fails](#rotation-degrades-rather-than-fails)), after
  which the pull succeeds again with a PSK-less peer set.

One asymmetry worth knowing during an upgrade: the header only corrects the
stored flag **downwards**. An upgraded agent gets `agent_psk` back to 1 from its
next `POST /api/node/wg/stats` report (~30 s), so PSKs start flowing one report
cycle after the upgrade, not on its first pull.

### When a node loses PSK support

A `1 -> 0` transition writes a `node.psk_capability_lost` audit entry whose meta
carries `psk_peers`, the number of peers on that node that already hold a PSK,
and logs the same at WARN. This is an outage that nothing can repair
server-side: those peers' `.conf` files already contain a `PresharedKey` line
the rolled-back agent will never apply, so **their configs must be
re-downloaded** (or the agent upgraded again). The *flag* downgrade is recorded
rather than refused - it is a report, not a request - and what actually gets
refused is that agent's next peer pull, as above.

### Rotation degrades rather than fails

Key rotation - manual, or from the `wg_key_rotation` job - is also the moment a
classic peer picks up a PSK, since the customer has to re-import the `.conf`
anyway. If a node in the group lags behind, rotation **proceeds without a PSK**:
`psk_enc` is cleared so the node's pull and the rendered `.conf` still agree, a
warning is logged, and a `wg_peer.psk_dropped` audit entry records the peer, the
node and the reason. Refusing would turn a security control into one that never
runs again.

Existing peers stay PSK-less until their next rotation or config re-download -
there is no retroactive fan-out, because every PSK change requires the customer
to re-import their config.

---

## Post-quantum-only hosts

By default a host offers hybrid ML-KEM *and* accepts classical X25519. A host
can instead be pinned to PQ-only: **host edit -> SSL & Protocols -> Post-quantum
only (reject clients without ML-KEM)**. That emits, for this host's SNI:

```json
{ "match": {"sni": ["example.com"]}, "curves": ["x25519mlkem768"], "protocol_min": "tls1.3" }
```

A client that cannot do hybrid ML-KEM then fails the handshake instead of
quietly negotiating classical X25519.

### Connection policies are merged per SNI, and the strictest wins

A TLS connection policy is matched **by SNI, before the request path is known**,
so it cannot be path-scoped. Several routes can share a hostname (different path
prefixes, plus aliases), and they all collapse into one policy entry:

- the host is **mTLS** if *any* route on it requires a client certificate;
- the host is **PQ-only** if *any* route on it is PQ-only.

The consequence is worth spelling out: **enabling mTLS on one path enforces
client certificates for every route on that hostname**, and the same is true of
PQ-only. This is a property of TLS, not a panel limitation.

If two routes on one hostname reference **different mTLS CAs**, only one can be
honoured: the first by route id wins, the other is dropped and the conflict is
logged (`conflicting mTLS trust anchors on one SNI`).

The policy list always ends with a catch-all `{}` so every host without its own
policy keeps plain TLS - see the [Security](#security-fix-in-the-same-release)
note below.

### Two gates before the policy is emitted

PQ-only is silently **not** emitted unless both hold:

1. **SSL is enabled for the host.** A connection policy is meaningless without
   TLS.
2. **The serving node declares Caddy 2.10 or newer**
   (`caddy_nodes.caddy_version`). That value is *operator-entered* on the node
   edit form, not probed. Caddy below 2.10 does not know the
   `x25519mlkem768` curve name and rejects the **entire** `/load`, which would
   freeze every route on that node - the same posture as the WAF/GeoIP/L4
   module gates.

How to check which applies:

- The host's SSL tab shows a pill: *"Post-quantum only - enforced"* (green),
  or *"Post-quantum only - saved, not active"* (amber) with the reason - SSL
  off, or the declared Caddy version of the node that blocks it, named.
- Every dropped policy is logged on push: `PQ-only TLS policy dropped: node has
  not declared Caddy 2.10+`, with `node_id`, `caddy_version` and `route_id`.
- **Settings -> Post-quantum** lists node Caddy versions and the PQ-only hosts.
  It counts **distinct SSL-enabled domains**, not routes: several path routes
  collapse into one connection policy per hostname, and a PQ-only route with
  SSL off emits no policy at all - counting either as a host would overstate
  the posture.

The host page checks **every node that serves the host** - the route's anchor
node plus its `route_node_assignments` fan-out, the same set the pusher walks -
and the amber caption names the first node that blocks it together with the
version that node declares. A fan-out peer on older Caddy therefore reads as
*"saved, not active"* instead of the page claiming an enforcement that the
push will silently drop on that node.

### Making a change actually take effect

PQ-only is a *node-level* TLS connection policy, not a route setting, so it only
becomes real when the node in question is pushed to. Two pushes that used to be
missing now happen on save:

- **Saving a host** queues a push for every node serving it - anchor plus
  `route_node_assignments` fan-out - and queues it *before* the anchor resync
  runs, on its own 10 s deadline. Queueing is pure database work while the
  resync does network I/O, and sharing one deadline let a single hung anchor eat
  the window and drop the healthy peers on the floor.
- **Saving a node** schedules a push for that node. Declaring Caddy 2.10 on the
  node edit form is what un-gates PQ-only for its routes; without a push the
  node kept serving the old config while the panel already reported the new
  capability. The same holds for the WAF, GeoIP and PROXY-protocol flags on that
  form.

So "is PQ-only in effect?" resolves to: the pill is green, **and** every serving
node has been pushed to since it declared 2.10+.

### Client compatibility

PQ-only breaks old clients on purpose. Roughly: Chrome < 131, Firefox < 132,
Safari / iOS < 26, `curl` not linked against OpenSSL 3.5+, Go clients older
than 1.24, and most monitoring and uptime bots. Only turn it on for endpoints
whose client population you control.

Behind Cloudflare, the CF edge does offer post-quantum key exchange to origins,
but verify it on that exact host before enabling - a proxied host that cannot
negotiate goes fully dark.

### Certificate renewal: TLS-ALPN-01 is disabled

The TLS-ALPN-01 challenge is itself a TLS handshake, and a CA validator that
does not offer ML-KEM gets rejected by the host's own policy - the certificate
would silently stop renewing and the host would go dark ~90 days later.

The panel therefore **disables that challenge** for every PQ-only subject. Each
one gets its own on-demand automation policy:

```json
{
  "subjects": ["pq.example.com"],
  "on_demand": true,
  "issuers": [{
    "module": "acme",
    "email": "you@example.com",
    "challenges": {"tls-alpn": {"disabled": true}}
  }]
}
```

Consequence: issuance must go through **HTTP-01 (port 80 reachable from the
internet)** or **DNS-01**. If neither works, the certificate is never issued -
the host fails at enable time instead of at the first renewal. That is the
trade: a visible failure now over a silent one in three months.

The policy is emitted only when the node is PQ-capable (Caddy 2.10+), because
only then is the PQ-only connection policy itself emitted. It sits *after* the
wildcard DNS-01 policies, so a PQ host inside a wildcard zone keeps DNS-01. A
node with no PQ-only route produces byte-identical JSON to before.

---

## Verifying

**Hybrid key exchange on a host** (needs OpenSSL 3.5 or newer; 3.6 works):

```bash
openssl s_client -connect example.com:443 -groups X25519MLKEM768 </dev/null 2>&1 \
  | grep -i 'Negotiated TLS1.3 group'
# Negotiated TLS1.3 group: X25519MLKEM768
```

For a PQ-only host, also confirm that a classical client is *rejected*:

```bash
openssl s_client -connect example.com:443 -groups X25519 </dev/null
# expect: handshake failure
```

On a normal (non-PQ-only) host the same command must still succeed - that is
the point of the default.

**In a browser:** Chrome DevTools -> Security -> View certificate /
Connection - the key exchange line reads `X25519MLKEM768`.

**WireGuard preshared keys**, on either side of either plane:

```bash
sudo wg show wg0        # mesh, on the panel host and on the node
sudo wg show wg-tun0    # customer tunnel, on the node
```

A peer with a PSK prints `preshared key: (hidden)`; without one the line is
absent. Confirm `latest handshake` is recent - a mismatched PSK shows as
handshakes that stop happening, not as an error.

**In the panel:** Settings -> Post-quantum (counts per layer), and the `PSK` /
`PSK pending` pill on the node list.

**In CI and at release:** the build fails if anything sets a `GODEBUG` that
disables ML-KEM, if non-test Go code sets `CurvePreferences`, or if the
`caddy:2.11.x` pins disagree across the deploy files, `docs/` and `README.md` -
a stale pin in the documentation sends operators to the wrong image, so it is
guarded like the real ones.

At release time the freshly built **amd64 image is started by digest** and
probed with `TestEdgePQHandshake`, which asserts both that a stock Go client
negotiates X25519MLKEM768 and that a classical X25519-only client still
connects. This runs **before** the `edge` / `latest` / semver tags are created:
the per-arch images already exist in the registry addressed by digest, so the
candidate can be run without publishing anything a consumer would pull. A
rejected build therefore leaves nothing pullable, rather than merely unsigned -
the manifest is assembled and cosign-signed only after the probe passes.

---

## Not covered (upstream-blocked)

None of these are HNDL risks - a signature only needs to be unforgeable *at the
time it is verified* - so they are tracked, not worked around.

| Item | Blocker |
|---|---|
| ML-DSA / SLH-DSA server certificates and chains | no public CA issues them, ACME has no profile for them, browsers do not verify them, and Go 1.26 has no `crypto/mldsa` |
| ACME account keys | same: ECDSA/RSA only, defined by the ACME ecosystem |
| OIDC token signatures | determined by the identity provider, not by HPG |
| Container image signatures (cosign) | keyless Sigstore signing is ECDSA/P-256 |

SSH is not used by the control plane, and Redis/MySQL traffic stays inside the
compose network (an unencrypted-transport question, not a post-quantum one).

---

## Security fix in the same release

Connection policies now always end with a catch-all `{}`. Caddy only supplies a
default policy when the policy list is **nil**; with any per-SNI policy present,
an unmatched ClientHello gets `no server TLS configuration available` and the
handshake dies. Before this fix, enabling mTLS on **one** host broke the TLS
handshake for **every other host on that node**, TLS-ALPN-01 renewals included.
Verified against a real Caddy 2.11.4 both ways.

If you had avoided mTLS because it "broke the other sites", that is why.

---

## Operational notes

- **`APP_SECRET` rotation.** `cmd/rotate-secret` now also re-encrypts
  `caddy_nodes.wg_psk_enc`, `wg_psk_pending_enc`, `wg_psk_token_enc` and
  `customer_wg_peer.psk_enc`, plus two columns that were missing before this
  release (`caddy_nodes.tunnel_privkey_e2`, `caddy_nodes.admin_proxy_key_enc`).
  Columns whose migration has not run yet are skipped with a `[skip]` line, so
  a newer image can rotate an older database.
- **Encryption purpose.** Every WireGuard secret at rest is sealed under the
  `wg` envelope purpose. Losing `APP_SECRET` makes the PSKs unrecoverable:
  clear and re-enable them, exactly as for the other node secrets.
- **Migrations.** `00142` (mesh PSK columns + token index), `00143`
  (`customer_wg_peer.psk_enc`, `caddy_nodes.agent_psk`), `00144`
  (`routes.tls_pq_only`). All additive, all defaulting to today's behaviour.

## Limitations

- Mesh PSK enable/rotate needs the node to reach the panel over public HTTPS.
  On an unusual install where the panel is only reachable *through the mesh*, a
  failed rekey cannot be repaired by the script - use **Clear PSK** plus the
  manual `sed` on the node.
- `caddy_nodes.caddy_version` is operator-entered, not probed. An undeclared or
  stale version means PQ-only is dropped for that node's routes; a version
  claimed but not installed means the node rejects the push.
- There is no global "PQ-only everywhere" switch, by design - it is a per-host
  opt-in with real client-compatibility cost.
- PQ-only disables TLS-ALPN-01 for that subject, so the host needs a working
  HTTP-01 (port 80) or DNS-01 path or it gets no certificate at all.
- Preshared keys protect the *key exchange*, not the endpoints. A node with a
  PSK whose disk is read still hands over everything it holds.

## See also

- [MTLS.md](MTLS.md) - client certificates; shares the connection-policy machinery
- [MULTI_NODE.md](MULTI_NODE.md#13-mesh-preshared-keys-rekeying-an-existing-node) - mesh rekey in the node lifecycle
- [SECURITY.md](SECURITY.md) - overall threat model and secret storage
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md#mesh-psk-mismatch-node-goes-offline-about-2-minutes-after-enabling) - PSK mismatch symptom
