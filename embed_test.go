package proxygateway_test

import (
	"io/fs"
	"strings"
	"testing"

	proxygateway "github.com/hostyt/proxy-gateway"
)

// TestMigrationsEmbedComplete fails if any migrations/*.sql file is missing
// from the embedded FS, or if a .sql file is found in a subdirectory (goose
// only reads the flat dir passed to UpContext).
func TestMigrationsEmbedComplete(t *testing.T) {
	sub, err := fs.Sub(proxygateway.MigrationsFS, "migrations")
	if err != nil {
		t.Fatalf("fs.Sub migrations: %v", err)
	}

	var found []string
	err = fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".sql") {
			return nil
		}
		// Goose only picks up files at depth 1 (no subdirectories).
		if strings.ContainsRune(path, '/') {
			t.Errorf("migration in subdirectory won't run: migrations/%s", path)
		}
		found = append(found, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded migrations: %v", err)
	}

	if len(found) == 0 {
		t.Fatal("no .sql files found in embedded migrations FS")
	}
	t.Logf("embedded migrations: %d files", len(found))
}

func TestMigrationsUseGooseDirectives(t *testing.T) {
	sub, err := fs.Sub(proxygateway.MigrationsFS, "migrations")
	if err != nil {
		t.Fatalf("fs.Sub migrations: %v", err)
	}

	err = fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}
		b, err := fs.ReadFile(sub, path)
		if err != nil {
			return err
		}
		s := string(b)
		if !strings.Contains(s, "-- +goose Up") {
			t.Errorf("migration %s missing -- +goose Up", path)
		}
		if !strings.Contains(s, "-- +goose Down") {
			t.Errorf("migration %s missing -- +goose Down", path)
		}
		if strings.Contains(s, "+migrate ") {
			t.Errorf("migration %s uses unsupported +migrate directive", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded migrations: %v", err)
	}
}
