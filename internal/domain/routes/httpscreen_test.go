package routes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/streamguard"
)

// noPin stands in for a resolver that is never consulted (IP-literal fixtures).
func noPin(host string, _ int) (string, error) { return host, nil }

// HPG-SEC-001: rows stored before HTTP target screening existed must not be
// re-emitted by boot push, resync or drift recovery - and a poisoned extra
// upstream or path rule must not take the whole route with it.
func TestScreenHTTPSetDropsInfraTargets(t *testing.T) {
	infra := screenTestInfra(t)
	built := []caddyapi.Route{
		{ID: "1", UpstreamIP: "10.0.0.5", UpstreamPort: 8080}, // customer origin, kept
		{ID: "2", UpstreamIP: "203.0.113.7", UpstreamPort: 8080},
		{ID: "3", UpstreamIP: "10.0.0.5", UpstreamPort: 2019},
		{ID: "4", UpstreamIP: "10.0.0.5", UpstreamPort: 8080,
			Upstreams: []caddyapi.Upstream{
				{Host: "10.0.0.6", Port: 8080},
				{Host: "127.0.0.1", Port: 2019},
			},
			LocationRules: []caddyapi.LocationRule{
				{Path: "/a", Action: "proxy", UpstreamHost: "10.0.0.7", UpstreamPort: 80},
				{Path: "/b", Action: "proxy", UpstreamHost: "10.66.0.4", UpstreamPort: 80},
			}},
		{ID: "5", Kind: "redirect", UpstreamIP: "0.0.0.0"}, // never dialed
	}
	out, ids, drops := screenHTTPSet(infra, built, []int64{1, 2, 3, 4, 5}, noPin)
	if len(out) != 3 || len(ids) != 3 {
		t.Fatalf("want 3 emitted routes, got %d (%v)", len(out), ids)
	}
	if ids[0] != 1 || ids[1] != 4 || ids[2] != 5 {
		t.Fatalf("ids must stay paired with routes, got %v", ids)
	}
	if len(drops) != 4 { // routes 2 and 3, plus one upstream and one rule of route 4
		t.Fatalf("want 4 drops, got %d", len(drops))
	}
	survivor := out[1]
	if len(survivor.Upstreams) != 1 || survivor.Upstreams[0].Host != "10.0.0.6" {
		t.Errorf("only the admin-API upstream may be dropped, got %+v", survivor.Upstreams)
	}
	if len(survivor.LocationRules) != 1 || survivor.LocationRules[0].Path != "/a" {
		t.Errorf("only the control-plane path rule may be dropped, got %+v", survivor.LocationRules)
	}
}

// fakePin resolves the test names and refuses the rebound ones, the way the
// real screener refuses an address that belongs to the control plane.
func fakePin(host string, _ int) (string, error) {
	switch host {
	case "app.tenant.example":
		return "198.51.100.10", nil
	case "api.tenant.example":
		return "198.51.100.11", nil
	case "pool-a.tenant.example":
		return "198.51.100.20", nil
	case "pool-b.tenant.example":
		return "198.51.100.21", nil
	case "sso.tenant.example":
		return "198.51.100.30", nil
	case "rebound.tenant.example":
		return "", errors.New("host rebound.tenant.example resolves to a blocked address")
	case "gone.tenant.example":
		return "", fmt.Errorf("%w: gone.tenant.example", streamguard.ErrUnresolved)
	}
	return host, nil
}

// A hostname handed to the node is re-resolved by the node on every dial, so
// the address that was screened is not necessarily the address that gets
// dialed. Every HTTP upstream kind is emitted as the address the panel
// screened, with the hostname kept for SNI.
func TestScreenHTTPSetPinsEveryUpstreamKind(t *testing.T) {
	infra := screenTestInfra(t)
	built := []caddyapi.Route{
		{ID: "1", UpstreamIP: "app.tenant.example", UpstreamPort: 443, UpstreamScheme: "https",
			LocationRules: []caddyapi.LocationRule{
				{Path: "/api", Action: "proxy", UpstreamHost: "api.tenant.example", UpstreamPort: 8443, UpstreamScheme: "https"},
			}},
		{ID: "2", UpstreamIP: "app.tenant.example", UpstreamPort: 443, UpstreamScheme: "https",
			Upstreams: []caddyapi.Upstream{
				{Host: "pool-a.tenant.example", Port: 8443},
				{Host: "10.0.0.9", Port: 8443},
			}},
	}
	out, _, drops := screenHTTPSet(infra, built, []int64{1, 2}, fakePin)
	if len(drops) != 0 || len(out) != 2 {
		t.Fatalf("nothing should drop: %d out, %d drops", len(out), len(drops))
	}

	primary := out[0]
	if primary.UpstreamIP != "198.51.100.10" || primary.PinnedSNI != "app.tenant.example" {
		t.Errorf("primary backend not pinned: dial=%q sni=%q", primary.UpstreamIP, primary.PinnedSNI)
	}
	lr := primary.LocationRules[0]
	if lr.UpstreamHost != "198.51.100.11" || lr.PinnedSNI != "api.tenant.example" {
		t.Errorf("location-rule upstream not pinned: dial=%q sni=%q", lr.UpstreamHost, lr.PinnedSNI)
	}
	pool := out[1]
	if pool.Upstreams[0].Host != "198.51.100.20" || pool.Upstreams[1].Host != "10.0.0.9" {
		t.Errorf("pool upstream not pinned: %+v", pool.Upstreams)
	}
	if pool.PinnedSNI != "pool-a.tenant.example" {
		t.Errorf("pool SNI must follow the pool, got %q", pool.PinnedSNI)
	}
	// The dial address must survive BuildRoute, with the origin hostname kept
	// as SNI so the https handshake still verifies against its own name.
	raw, err := json.Marshal(caddyapi.BuildRoute(primary))
	if err != nil {
		t.Fatalf("marshal route: %v", err)
	}
	js := string(raw)
	for _, want := range []string{
		`"dial":"198.51.100.10:443"`,
		`"server_name":"app.tenant.example"`,
		`"dial":"198.51.100.11:8443"`,
		`"server_name":"api.tenant.example"`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("emitted config missing %s: %s", want, js)
		}
	}
}

// A name that no longer screens clean takes only its own target with it.
func TestScreenHTTPSetDropsRebindOnEveryUpstreamKind(t *testing.T) {
	infra := screenTestInfra(t)
	built := []caddyapi.Route{
		{ID: "1", UpstreamIP: "rebound.tenant.example", UpstreamPort: 443},
		{ID: "2", UpstreamIP: "app.tenant.example", UpstreamPort: 443,
			Upstreams: []caddyapi.Upstream{
				{Host: "rebound.tenant.example", Port: 8443},
				{Host: "pool-b.tenant.example", Port: 8443},
			},
			LocationRules: []caddyapi.LocationRule{
				{Path: "/api", Action: "proxy", UpstreamHost: "rebound.tenant.example", UpstreamPort: 8443},
				{Path: "/ok", Action: "proxy", UpstreamHost: "api.tenant.example", UpstreamPort: 8443},
			}},
		// Never resolved, never pinned: emitting the name would hand the
		// destination back to the node unchecked.
		{ID: "3", UpstreamIP: "gone.tenant.example", UpstreamPort: 443},
	}
	out, ids, drops := screenHTTPSet(infra, built, []int64{1, 2, 3}, fakePin)
	if len(out) != 1 || ids[0] != 2 {
		t.Fatalf("only the partially poisoned route survives, got ids %v", ids)
	}
	if len(drops) != 4 {
		t.Fatalf("want 4 drops (2 routes, 1 upstream, 1 rule), got %d", len(drops))
	}
	survivor := out[0]
	if len(survivor.Upstreams) != 1 || survivor.Upstreams[0].Host != "198.51.100.21" {
		t.Errorf("clean pool member must stay, pinned: %+v", survivor.Upstreams)
	}
	if len(survivor.LocationRules) != 1 || survivor.LocationRules[0].UpstreamHost != "198.51.100.11" {
		t.Errorf("clean rule must stay, pinned: %+v", survivor.LocationRules)
	}
}

// Pinning is skipped exactly where an operator accepted node-side resolution,
// and the deny set still runs on every one of those.
func TestScreenHTTPSetKeepsNamesTheNodeResolves(t *testing.T) {
	infra := screenTestInfra(t)
	built := []caddyapi.Route{
		{ID: "1", UpstreamIP: "app.tenant.example", UpstreamPort: 443, ResolveNodeSide: true},
		{ID: "2", UpstreamIP: "app.tenant.example", UpstreamPort: 443, External: true},
		// https pool over two different origins: one transport carries one
		// server_name, so these keep their names.
		{ID: "5", UpstreamIP: "app.tenant.example", UpstreamPort: 443, UpstreamScheme: "https",
			Upstreams: []caddyapi.Upstream{
				{Host: "pool-a.tenant.example", Port: 8443},
				{Host: "pool-b.tenant.example", Port: 8443},
			}},
	}
	out, _, drops := screenHTTPSet(infra, built, []int64{1, 2, 5}, fakePin)
	if len(drops) != 0 || len(out) != 3 {
		t.Fatalf("nothing should drop: %d out, %d drops", len(out), len(drops))
	}
	for _, r := range out[:2] {
		if r.UpstreamIP != "app.tenant.example" || r.PinnedSNI != "" {
			t.Errorf("route %s must keep its name: dial=%q sni=%q", r.ID, r.UpstreamIP, r.PinnedSNI)
		}
	}
	if out[2].Upstreams[0].Host != "pool-a.tenant.example" || out[2].PinnedSNI != "" {
		t.Errorf("mixed-name https pool must keep its names: %+v", out[2])
	}
	// The deny set is not waived by any of it.
	named := screenTestInfra(t)
	named.Add("node1.example.com")
	blocked := []caddyapi.Route{{ID: "9", UpstreamIP: "node1.example.com", UpstreamPort: 443, ResolveNodeSide: true}}
	if _, _, d := screenHTTPSet(named, blocked, []int64{9}, fakePin); len(d) != 1 {
		t.Errorf("a control-plane hostname must drop even when the node resolves it, got %d drops", len(d))
	}
}

// DNS that stops answering must not hand the destination back to the node:
// the last screened address keeps being emitted.
func TestPinHTTPTargetFreezesLastScreenedAddress(t *testing.T) {
	infra := screenTestInfra(t)
	pinnedAddrs.Lock()
	pinnedAddrs.m = map[string]pinEntry{}
	pinnedAddrs.Unlock()

	calls := 0
	orig := pinResolve
	pinResolve = func(_ context.Context, _ *streamguard.InfraTargets, host string, _ int) (string, error) {
		calls++
		if calls == 1 {
			return "198.51.100.10", nil
		}
		return "", fmt.Errorf("%w: %s", streamguard.ErrUnresolved, host)
	}
	t.Cleanup(func() { pinResolve = orig })

	got, err := pinHTTPTarget(context.Background(), infra, "app.tenant.example", 443, nil)
	if err != nil || got != "198.51.100.10" {
		t.Fatalf("first pin: %q %v", got, err)
	}
	// Age the entry past the freshness window so the failing lookup is reached.
	pinnedAddrs.Lock()
	pinnedAddrs.m["app.tenant.example|443"] = pinEntry{addr: "198.51.100.10", at: time.Now().Add(-time.Hour)}
	pinnedAddrs.Unlock()

	got, err = pinHTTPTarget(context.Background(), infra, "app.tenant.example", 443, nil)
	if err != nil || got != "198.51.100.10" {
		t.Fatalf("resolution failure must keep the screened address, got %q %v", got, err)
	}
	// A name with no screened address on record stays refused.
	if _, err := pinHTTPTarget(context.Background(), infra, "never-seen.tenant.example", 443, nil); err == nil {
		t.Error("an unknown name that does not resolve must not be authorised")
	}
}

// With a pool present nothing dials the single backend field, so a stale name
// left in it must not be able to take the route down - while the members that
// are dialed stay fully screened.
func TestScreenHTTPSetIgnoresUnusedPrimaryWhenPoolPresent(t *testing.T) {
	infra := screenTestInfra(t)
	built := []caddyapi.Route{
		{ID: "1", UpstreamIP: "gone.tenant.example", UpstreamPort: 443,
			Upstreams: []caddyapi.Upstream{
				{Host: "pool-a.tenant.example", Port: 8443},
				{Host: "rebound.tenant.example", Port: 8443},
			}},
	}
	out, _, drops := screenHTTPSet(infra, built, []int64{1}, fakePin)
	if len(out) != 1 {
		t.Fatalf("route must survive an unused primary: %d drops", len(drops))
	}
	if len(out[0].Upstreams) != 1 || out[0].Upstreams[0].Host != "198.51.100.20" {
		t.Errorf("dialed pool members stay screened and pinned: %+v", out[0].Upstreams)
	}
	if len(drops) != 1 || drops[0].part != "upstream" {
		t.Errorf("want exactly the poisoned upstream dropped, got %+v", drops)
	}
}

// HPG-SEC-001a: a custom DNS resolver (or an auto-bound tunnel peer) is not a
// waiver. The panel still picks and screens the address, and the resolver that
// no longer decides anything is dropped from the emitted config.
func TestScreenHTTPSetPinsResolverBackedNames(t *testing.T) {
	infra := screenTestInfra(t)
	built := []caddyapi.Route{
		{ID: "1", UpstreamIP: "app.tenant.example", UpstreamPort: 443, BackendResolver: "10.0.0.53"},
		{ID: "2", UpstreamIP: "app.tenant.example", UpstreamPort: 443, DNSResolverIP: "10.0.0.53"},
		{ID: "3", UpstreamIP: "app.tenant.example", UpstreamPort: 443, DNSResolverViaWGPeerIP: "10.77.0.2"},
		// The tenant's own resolver answering with infra must not get through.
		{ID: "4", UpstreamIP: "rebound.tenant.example", UpstreamPort: 443, DNSResolverViaWGPeerIP: "10.77.0.2"},
	}
	out, _, drops := screenHTTPSet(infra, built, []int64{1, 2, 3, 4}, fakePin)
	if len(out) != 3 || len(drops) != 1 || drops[0].part != "primary backend" {
		t.Fatalf("want 3 kept and the poisoned name dropped: %d out, %+v", len(out), drops)
	}
	for _, r := range out {
		if r.UpstreamIP != "198.51.100.10" || r.PinnedSNI != "app.tenant.example" {
			t.Errorf("route %s not pinned by the panel: dial=%q sni=%q", r.ID, r.UpstreamIP, r.PinnedSNI)
		}
		if r.BackendResolver != "" || r.DNSResolverIP != "" || r.DNSResolverViaWGPeerIP != "" {
			t.Errorf("route %s still carries a node-side resolver: %+v", r.ID, r)
		}
	}
}

// HPG-SEC-001a: a bound tunnel peer dials the peer address the panel screened;
// only the super_admin waiver hands a name to the node.
func TestTunnelBackendDialPinsNameToPeer(t *testing.T) {
	const peer = "10.77.0.2"
	cases := []struct {
		name                      string
		external, resolveNodeSide bool
		backend, peerIP, want     string
	}{
		{"name collapses to peer", false, false, "app.tenant.example", peer, peer},
		{"waiver keeps the name", false, true, "app.tenant.example", peer, "app.tenant.example"},
		{"external keeps its fqdn", true, false, "origin.example.com", peer, "origin.example.com"},
		{"literal untouched", false, false, "10.77.0.9", peer, "10.77.0.9"},
		{"no tunnel, no collapse", false, false, "app.tenant.example", "", "app.tenant.example"},
	}
	for _, c := range cases {
		if got := tunnelBackendDial(c.external, c.resolveNodeSide, c.backend, c.peerIP); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

// HPG-SEC-001b: the SSO provider is a tenant-controlled dial target - it feeds
// the UNAUTHENTICATED outpost passthrough - so it is screened and pinned like
// any other, and a route whose provider fails the screen is held back.
func TestScreenHTTPSetScreensSSOProvider(t *testing.T) {
	infra := screenTestInfra(t)
	built := []caddyapi.Route{
		{ID: "1", UpstreamIP: "10.0.0.5", UpstreamPort: 8080, SSOProviderURL: "https://sso.tenant.example"},
		{ID: "2", UpstreamIP: "10.0.0.5", UpstreamPort: 8080, SSOProviderURL: "http://203.0.113.7:9000"},
		{ID: "3", UpstreamIP: "10.0.0.5", UpstreamPort: 8080, SSOProviderURL: "http://10.0.0.5:2019"},
		{ID: "4", UpstreamIP: "10.0.0.5", UpstreamPort: 8080, SSOProviderURL: "http://10.66.0.9:9000"},
		// Tunnel-bound provider: the peer address is screened as a literal.
		{ID: "5", UpstreamIP: "10.0.0.5", UpstreamPort: 8080,
			SSOProviderURL: "https://sso.tenant.example", SSOResolver: "10.66.0.9"},
		// A redirect route emits the SSO subroutes too - no free pass.
		{ID: "6", Kind: "redirect", RedirectURL: "https://elsewhere.example",
			SSOProviderURL: "http://203.0.113.7:9000"},
	}
	out, _, drops := screenHTTPSet(infra, built, []int64{1, 2, 3, 4, 5, 6}, fakePin)
	if len(out) != 1 || len(drops) != 5 {
		t.Fatalf("only the clean provider may be emitted: %d out, %d drops", len(out), len(drops))
	}
	for _, d := range drops {
		if d.part != "sso provider" {
			t.Errorf("wrong drop part %q", d.part)
		}
	}
	if out[0].SSOResolver != "198.51.100.30" {
		t.Fatalf("provider name not pinned: %q", out[0].SSOResolver)
	}
	// The pin must survive emission, with the provider name kept as SNI.
	raw, err := json.Marshal(caddyapi.BuildRoute(out[0]))
	if err != nil {
		t.Fatalf("marshal route: %v", err)
	}
	js := string(raw)
	for _, want := range []string{`"dial":"198.51.100.30:443"`, `"server_name":"sso.tenant.example"`} {
		if !strings.Contains(js, want) {
			t.Errorf("emitted SSO config missing %s: %s", want, js)
		}
	}
	if strings.Contains(js, "sso.tenant.example:443") {
		t.Errorf("unpinned provider name still dialed: %s", js)
	}
}
