package routes

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// seedConsoleFixture: plan allowing external + path routing + websocket.
func seedConsoleFixture(t *testing.T) (*Service, int64) {
	t.Helper()
	db := newPushTestDB(t)
	nodeID := seedCapacityFixture(t, db, 100)
	if _, err := db.Exec(`UPDATE plans SET external_proxy_enabled = 1, path_routing_enabled = 1 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	svc := newMTLSCreateSvc(t, db)
	svc.ExternalUpstreamAllowlist = []string{"*.console.example", "exact.internal.example"}
	return svc, nodeID
}

func stubScreen(t *testing.T, fn func(context.Context, string) error) {
	t.Helper()
	prev := screenExternalHost
	screenExternalHost = fn
	t.Cleanup(func() { screenExternalHost = prev })
}

func consoleInput(host string) CreateInput {
	return CreateInput{
		ServiceID: 1, Domain: "console.panel.example", PathPrefix: "/console/abc123",
		SSL: true, WebSocket: true, ForceHTTPS: true,
		External: true, ExternalHost: host, UpstreamHostHeader: host,
		StripPathPrefix: true, UpstreamPath: "/kvm/tok", TTLSeconds: 600,
	}
}

func TestCreate_EphemeralExternalRoute_BuildsRewriteAndVerifiedTLS(t *testing.T) {
	svc, nodeID := seedConsoleFixture(t)
	stubScreen(t, func(context.Context, string) error { return nil })
	ctx := context.Background()

	id, err := svc.Create(ctx, 0, consoleInput("vps1.console.example"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var strip int
	var upPath string
	var hasExpiry int
	if err := svc.DB.QueryRow(`SELECT strip_path_prefix, upstream_path, expires_at IS NOT NULL FROM routes WHERE id = ?`, id).
		Scan(&strip, &upPath, &hasExpiry); err != nil {
		t.Fatal(err)
	}
	if strip != 1 || upPath != "/kvm/tok" || hasExpiry != 1 {
		t.Fatalf("stored strip=%d path=%q expiry=%d", strip, upPath, hasExpiry)
	}

	if _, err := svc.DB.Exec("UPDATE routes SET status = 'active' WHERE id = ?", id); err != nil {
		t.Fatal(err)
	}
	built, ids, err := svc.buildRoutesForNode(ctx, nodeID)
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("build: ids=%v err=%v", ids, err)
	}
	r := built[0]
	if !r.External || !r.WebSocket || !r.StripPathPrefix || r.UpstreamPathPrefix != "/kvm/tok" {
		t.Fatalf("built route lost fields: %+v", r)
	}
	cfg, _ := json.Marshal(caddyapi.BuildRoute(r))
	s := string(cfg)
	for _, want := range []string{
		`"strip_path_prefix":"/console/abc123"`,
		`"uri":"/kvm/tok{http.request.uri.path}"`,
		`"server_name":"vps1.console.example"`,
		`"Host":["vps1.console.example"]`,
		`"dial":"vps1.console.example:443"`,
		`"stream_close_delay":"15m"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("config missing %s\n%s", want, s)
		}
	}
	if strings.Contains(s, "insecure_skip_verify") {
		t.Error("external upstream must verify TLS")
	}
	if strings.Index(s, `"strip_path_prefix"`) > strings.Index(s, `"reverse_proxy"`) {
		t.Error("rewrite must run before reverse_proxy")
	}
}

func TestCreate_ExternalAllowlistAndSSRF(t *testing.T) {
	svc, _ := seedConsoleFixture(t)
	ctx := context.Background()
	screened := ""
	stubScreen(t, func(_ context.Context, h string) error {
		screened = h
		return errors.New("resolves to 10.0.0.1")
	})

	// Wildcard hit that resolves private: refused.
	if _, err := svc.Create(ctx, 0, consoleInput("evil.console.example")); !errors.Is(err, ErrExternalHostUnsafe) {
		t.Fatalf("private wildcard host: err=%v", err)
	}
	if screened != "evil.console.example" {
		t.Fatalf("wildcard hit not screened: %q", screened)
	}
	// Exact entry is operator consent: not screened.
	screened = ""
	in := consoleInput("exact.internal.example")
	in.PathPrefix = "/console/other"
	if _, err := svc.Create(ctx, 0, in); err != nil {
		t.Fatalf("exact entry: %v", err)
	}
	if screened != "" {
		t.Fatal("exact entry must not be screened")
	}
	// Not allowlisted, zone apex, IP literal, suffix trick.
	for _, h := range []string{"console.example", "127.0.0.1", "x.console.example.attacker.net", "localhost", "badconsole.example", "a_b..console.example"} {
		in := consoleInput(h)
		in.PathPrefix = "/console/" + strings.ReplaceAll(h, ".", "")
		if _, err := svc.Create(ctx, 0, in); !errors.Is(err, ErrExternalHostNotAllowed) {
			t.Errorf("%s: err=%v, want not allowed", h, err)
		}
	}
}

func TestCreate_RejectsBadRewrite(t *testing.T) {
	svc, _ := seedConsoleFixture(t)
	stubScreen(t, func(context.Context, string) error { return nil })
	ctx := context.Background()
	cases := map[string]func(*CreateInput){
		"dotdot":        func(in *CreateInput) { in.UpstreamPath = "/a/../b" },
		"placeholder":   func(in *CreateInput) { in.UpstreamPath = "/{env.SECRET}" },
		"relative":      func(in *CreateInput) { in.UpstreamPath = "kvm" },
		"query":         func(in *CreateInput) { in.UpstreamPath = "/kvm?x=1" },
		"ttl too long":  func(in *CreateInput) { in.TTLSeconds = maxRouteTTL + 1 },
		"ttl negative":  func(in *CreateInput) { in.TTLSeconds = -1 },
		"strip no path": func(in *CreateInput) { in.PathPrefix = "" },
		"path not extern": func(in *CreateInput) {
			in.External = false
			in.UpstreamPort = 10001
		},
	}
	for name, mut := range cases {
		in := consoleInput("vps1.console.example")
		mut(&in)
		if _, err := svc.Create(ctx, 0, in); !errors.Is(err, ErrInvalidRewrite) {
			t.Errorf("%s: err=%v, want ErrInvalidRewrite", name, err)
		}
	}
}

func TestDeleteExpired_RemovesAndBuildSkips(t *testing.T) {
	svc, nodeID := seedConsoleFixture(t)
	stubScreen(t, func(context.Context, string) error { return nil })
	ctx := context.Background()
	live, err := svc.Create(ctx, 0, consoleInput("vps1.console.example"))
	if err != nil {
		t.Fatal(err)
	}
	in := consoleInput("vps2.console.example")
	in.PathPrefix = "/console/old"
	old, err := svc.Create(ctx, 0, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB.Exec(`UPDATE routes SET status = 'active'`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DB.Exec(`UPDATE routes SET expires_at = datetime('now', '-1 minutes') WHERE id = ?`, old); err != nil {
		t.Fatal(err)
	}
	_, ids, err := svc.buildRoutesForNode(ctx, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != live {
		t.Fatalf("expired route emitted: ids=%v", ids)
	}
	svc.DeleteExpired(ctx)
	var n int
	_ = svc.DB.QueryRow(`SELECT COUNT(*) FROM routes WHERE id = ?`, old).Scan(&n)
	if n != 0 {
		t.Fatal("expired route not deleted")
	}
	_ = svc.DB.QueryRow(`SELECT COUNT(*) FROM routes WHERE id = ?`, live).Scan(&n)
	if n != 1 {
		t.Fatal("live route deleted")
	}
}
