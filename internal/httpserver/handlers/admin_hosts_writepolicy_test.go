package handlers

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	_ "modernc.org/sqlite"
)

// HPG-SEC-004: the write path used a denylist while emission used the
// http.request.* allow-list, so these values saved with no error and then
// quarantined the whole host at the next push. Both halves are one policy now.
func TestHeaderWritePolicyMatchesEmission(t *testing.T) {
	for _, bad := range []string{
		"X-A: {vars.x}", "X-A: {time.now}", "X-A: {env.APP_SECRET}",
		"{vars.name}: v",
	} {
		if _, err := parseHeaderLines(bad); err == nil {
			t.Errorf("custom header %q must be refused at write time", bad)
		}
	}
	got, err := parseHeaderLines("X-Forwarded-Host: {http.request.host}")
	if err != nil || !strings.Contains(got, "http.request.host") {
		t.Errorf("request placeholders must stay allowed: %q %v", got, err)
	}
}

func TestLocationRuleWritePolicyMatchesEmission(t *testing.T) {
	cases := []struct {
		field, value string
	}{
		{"loc_redirect_url[]", "https://x.example/{vars.x}"},
		{"loc_redirect_url[]", "https://x.example/{time.now}"},
		{"loc_rewrite_uri[]", "/a{vars.x}"},
		{"loc_rewrite_uri[]", "/a{time.now}"},
	}
	for _, c := range cases {
		action := "redirect"
		if c.field == "loc_rewrite_uri[]" {
			action = "rewrite"
		}
		form := url.Values{
			"loc_path[]":   {"/a"},
			"loc_action[]": {action},
			c.field:        {c.value},
		}
		if _, err := sanitizeLocationRules(form); err == nil {
			t.Errorf("%s %q must be refused at write time", c.field, c.value)
		}
	}
	form := url.Values{
		"loc_path[]":        {"/a"},
		"loc_action[]":      {"rewrite"},
		"loc_rewrite_uri[]": {"/index.php{http.request.uri}"},
	}
	if _, err := sanitizeLocationRules(form); err != nil {
		t.Errorf("request placeholders must stay allowed in a rewrite: %v", err)
	}
}

// HPG-SEC-006: the clone copied waf_directives verbatim, which put arbitrary
// SecLang on a new route without passing the write-time gate.
func TestCloneSkipsOperatorOnlyColumns(t *testing.T) {
	for _, col := range []string{"waf_directives", "custom_config"} {
		if !cloneSkipColumns[col] {
			t.Errorf("clone must not copy %s", col)
		}
	}
}

func wafToggleDB(t *testing.T, directives string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE routes (id INTEGER PRIMARY KEY, waf_directives TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO routes (id, waf_directives) VALUES (1, ?)`, directives); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return db
}

// HPG-SEC-006: re-activating a route re-publishes its stored SecLang into the
// node's shared Coraza config, so the toggle must re-run the write-time gate
// instead of trusting whatever privilege wrote the row.
func TestRevalidateStoredWAFOnReactivation(t *testing.T) {
	arbitrary := "SecRuleEngine Off"
	structured := "SecRuleRemoveById 942100"

	cases := []struct {
		name       string
		directives string
		role       string
		wantErr    bool
	}{
		{"arbitrary by scoped admin", arbitrary, "admin", true},
		{"arbitrary by super admin", arbitrary, "super_admin", false},
		{"structured by scoped admin", structured, "admin", false},
		{"empty", "", "admin", false},
	}
	for _, c := range cases {
		db := wafToggleDB(t, c.directives)
		h := &AdminHandlers{DB: func() *sql.DB { return db }}
		err := h.revalidateStoredWAF(context.Background(), &auth.Session{Role: c.role}, 1)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
	}

	// Fail closed: an unreadable row must not re-activate.
	missing := wafToggleDB(t, arbitrary)
	h := &AdminHandlers{DB: func() *sql.DB { return missing }}
	if err := h.revalidateStoredWAF(context.Background(), &auth.Session{Role: "super_admin"}, 999); err == nil {
		t.Error("unreadable route must fail closed")
	}
}

// The write gate: a non-super_admin may keep a stored arbitrary directive
// (otherwise a legacy row locks them out of every other field) but may never
// introduce a new one. The structured suppression keeps working for everyone.
func TestCheckWAFDirectivesWriteGate(t *testing.T) {
	db := wafToggleDB(t, "SecRuleEngine Off")
	h := &AdminHandlers{DB: func() *sql.DB { return db }}
	scoped := &auth.Session{Role: "admin"}
	super := &auth.Session{Role: "super_admin"}
	ctx := context.Background()

	if err := h.checkWAFDirectives(ctx, scoped, 1, "SecRuleEngine Off"); err != nil {
		t.Errorf("unchanged stored value must not block an unrelated edit: %v", err)
	}
	if err := h.checkWAFDirectives(ctx, scoped, 1, "SecAuditEngine On"); err == nil {
		t.Error("a non-super_admin must not introduce new arbitrary SecLang")
	}
	if err := h.checkWAFDirectives(ctx, scoped, 1, "SecRuleRemoveById 942100"); err != nil {
		t.Errorf("structured suppression must stay available: %v", err)
	}
	if err := h.checkWAFDirectives(ctx, super, 1, "SecAuditEngine On"); err != nil {
		t.Errorf("super_admin keeps arbitrary SecLang: %v", err)
	}
	if err := h.checkWAFDirectives(ctx, super, 1, "Include /etc/passwd"); err == nil {
		t.Error("a non-Sec* directive is storable by nobody")
	}
}

// "Scoped to all clients" is not platform-operator privilege; arbitrary
// SecLang is super_admin only.
func TestArbitrarySecLangIsSuperAdminOnly(t *testing.T) {
	for _, role := range []string{"admin", "reseller_admin", ""} {
		if isSuperAdmin(&auth.Session{Role: role}) {
			t.Errorf("role %q must not be treated as super_admin", role)
		}
		if err := caddyapi.ValidateWAFDirectives("SecRuleEngine Off", isSuperAdmin(&auth.Session{Role: role})); err == nil {
			t.Errorf("role %q must not be able to write arbitrary SecLang", role)
		}
		if err := caddyapi.ValidateWAFDirectives("SecRuleRemoveById 942100", isSuperAdmin(&auth.Session{Role: role})); err != nil {
			t.Errorf("role %q must keep the structured suppression: %v", role, err)
		}
	}
	if !isSuperAdmin(&auth.Session{Role: "super_admin"}) {
		t.Error("super_admin must be unrestricted")
	}
}
