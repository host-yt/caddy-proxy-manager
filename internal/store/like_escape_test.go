package store

import (
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SQLite rejects a two-character ESCAPE literal; the helper must give it one
// backslash and still treat \_ and \% as literal characters.
func TestLikeEscapeBackslash_SQLite(t *testing.T) {
	prev := Driver()
	SetDriver("sqlite3")
	t.Cleanup(func() { SetDriver(prev) })

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tc := range []struct {
		value, pattern string
		want           bool
	}{
		{"a_b", `a\_b`, true},
		{"axb", `a\_b`, false}, // escaped _ is not a wildcard
		{"50%", `50\%`, true},
		{"500", `50\%`, false},
	} {
		var got bool
		if err := db.QueryRow(`SELECT ? LIKE ? `+LikeEscapeBackslash(), tc.value, tc.pattern).Scan(&got); err != nil {
			t.Fatalf("%q LIKE %q: %v", tc.value, tc.pattern, err)
		}
		if got != tc.want {
			t.Errorf("%q LIKE %q = %v, want %v", tc.value, tc.pattern, got, tc.want)
		}
	}
}

func TestLikeEscapeBackslash_MySQLLiteral(t *testing.T) {
	prev := Driver()
	SetDriver("mysql")
	t.Cleanup(func() { SetDriver(prev) })
	// MySQL reads '\\' as a single backslash (default sql_mode).
	if got := LikeEscapeBackslash(); got != `ESCAPE '\\'` {
		t.Fatalf("mysql = %s", got)
	}
}

// A hard-coded ESCAPE literal is right on exactly one dialect: `'\\'` breaks
// SQLite, "'\\'" (a Go-escaped single backslash) breaks MySQL. Every LIKE
// escape in runtime code goes through LikeEscapeBackslash.
func TestNoHardcodedLikeEscape(t *testing.T) {
	root := filepath.Join("..", "..")
	re := regexp.MustCompile(`ESCAPE\s+'`)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "terraform-provider-hpg", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			filepath.Base(path) == "driver.go" {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if re.MatchString(line) {
				t.Errorf("%s:%d: hard-coded LIKE ESCAPE literal; use store.LikeEscapeBackslash()", path, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// LikeContains + LikeEscapeBackslash match user input literally: "my_app"
// must not find "myXapp" (the AI assistant's LIMIT 1 lookups relied on it).
func TestLikeContains_Literal(t *testing.T) {
	prev := Driver()
	SetDriver("sqlite3")
	t.Cleanup(func() { SetDriver(prev) })
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tc := range []struct {
		value, term string
		want        bool
	}{
		{"my_app.example.com", "my_app", true},
		{"myXapp.example.com", "my_app", false},
		{"50%off.example", "50%", true},
		{"500ff.example", "50%", false},
		{`a\b`, `a\b`, true},
	} {
		var got bool
		if err := db.QueryRow(`SELECT ? LIKE ? `+LikeEscapeBackslash(), tc.value, LikeContains(tc.term)).Scan(&got); err != nil {
			t.Fatalf("%q ~ %q: %v", tc.value, tc.term, err)
		}
		if got != tc.want {
			t.Errorf("%q contains %q = %v, want %v", tc.value, tc.term, got, tc.want)
		}
	}
}
