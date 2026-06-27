package aitools

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestSpecsCoverAllTools(t *testing.T) {
	r := New(nil)
	specs := r.Specs()
	if len(specs) != len(r.order) || len(specs) == 0 {
		t.Fatalf("specs len = %d, tools = %d", len(specs), len(r.order))
	}
	want := map[string]bool{
		"list_nodes": true, "list_routes": true, "list_clients": true,
		"list_services": true, "get_traffic_stats": true, "node_health": true,
	}
	for _, s := range specs {
		if s.Name == "" || s.Description == "" || len(s.Schema) == 0 {
			t.Fatalf("incomplete spec: %+v", s)
		}
		// Schema must be valid JSON so providers accept it.
		var js any
		if err := json.Unmarshal(s.Schema, &js); err != nil {
			t.Fatalf("tool %s schema invalid: %v", s.Name, err)
		}
		delete(want, s.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing tools: %v", want)
	}
}

func TestCallUnknownTool(t *testing.T) {
	r := New(nil)
	_, err := r.Call(context.Background(), "drop_tables", nil)
	if !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("want ErrUnknownTool, got %v", err)
	}
}

func TestCallNilDBSafe(t *testing.T) {
	r := New(nil)
	out, err := r.Call(context.Background(), "list_nodes", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("nil-db Call err: %v", err)
	}
	if !strings.Contains(out, "database unavailable") {
		t.Fatalf("nil-db should report unavailable, got %q", out)
	}
}

func TestClampLimit(t *testing.T) {
	cases := []struct{ in, def, max, want int }{
		{0, 50, 200, 50}, {-5, 50, 200, 50}, {10, 50, 200, 10}, {999, 50, 200, 200},
	}
	for _, c := range cases {
		if got := clampLimit(c.in, c.def, c.max); got != c.want {
			t.Fatalf("clampLimit(%d,%d,%d) = %d, want %d", c.in, c.def, c.max, got, c.want)
		}
	}
}

func TestItoa(t *testing.T) {
	for _, c := range []struct {
		n    int
		want string
	}{{0, "0"}, {7, "7"}, {50, "50"}, {-12, "-12"}, {200, "200"}} {
		if got := itoa(c.n); got != c.want {
			t.Fatalf("itoa(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

// TestNoSecretColumns is a static guard: the tool query source must never name a
// secret column. This fails loudly if someone adds a tool that selects one.
// Line comments are stripped first so the explanatory notes (which name the
// excluded columns on purpose) do not trip the scan.
func TestNoSecretColumns(t *testing.T) {
	src, err := os.ReadFile("tools.go")
	if err != nil {
		t.Fatalf("read tools.go: %v", err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	lower := strings.ToLower(code.String())
	forbidden := []string{
		"password_hash", "totp_secret", "code_hash", "key_hash",
		"_enc", "_key", "privkey", "private_key", "agent_token", "token_hash",
		"recovery_code", "tunnel_privkey", "key_prefix",
		"insert ", "update ", "delete ", "drop ", "alter ", "truncate ",
	}
	for _, f := range forbidden {
		if strings.Contains(lower, f) {
			t.Fatalf("tools.go must not reference %q (secret column or mutation)", f)
		}
	}
}
