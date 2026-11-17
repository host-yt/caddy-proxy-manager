package handlers

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/backup"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
)

const testHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func backupEditHandlers(t *testing.T) (*AdminHandlers, *backup.Service) {
	t.Helper()
	db := mtlsTLSEditDB(t)
	st, err := installstate.New(t.TempDir(), strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &backup.Service{DB: func() *sql.DB { return db }, State: st, Logger: logger}
	h := editFormHandlers(t, db)
	h.Backups = svc
	return h, svc
}

func postBackupForm(h http.HandlerFunc, target string, id string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rctx := chi.NewRouteContext()
	if id != "" {
		rctx.URLParams.Add("id", id)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.ContextWithSession(ctx, &auth.Session{UserID: 1, Role: "super_admin"})
	rec := httptest.NewRecorder()
	h(rec, req.WithContext(ctx))
	return rec
}

func sftpForm(name, host string, lan bool) url.Values {
	f := url.Values{"name": {name}, "kind": {"sftp"}, "cfg_host": {host}, "cfg_user": {"backup"},
		"cfg_password": {"s3cret-pass"}, "cfg_host_key": {testHostKey}, "cfg_path": {"/volume1/hpg"}}
	if lan {
		f.Set("cfg_allow_private", "1")
	}
	return f
}

// #148: a NAS on the LAN is refused by default and accepted once the
// destination is marked as living on a private network.
func TestBackupDestinationLAN(t *testing.T) {
	h, svc := backupEditHandlers(t)
	rec := postBackupForm(h.BackupsCreateDestination, "/admin/backups/destinations", "", sftpForm("nas", "192.168.0.12", false))
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") || !strings.Contains(loc, "forbidden") {
		t.Fatalf("private NAS without opt-in: Location %q, want an ssrf error", loc)
	}
	rec = postBackupForm(h.BackupsCreateDestination, "/admin/backups/destinations", "", sftpForm("nas", "192.168.0.12", true))
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "err=") {
		t.Fatalf("private NAS with opt-in refused: %q", loc)
	}
	dests, err := svc.LoadDestinations(context.Background(), false)
	if err != nil || len(dests) != 1 || dests[0].Config["allow_private"] != "1" {
		t.Fatalf("stored destinations = %+v (%v)", dests, err)
	}
	// The opt-in never reaches loopback.
	rec = postBackupForm(h.BackupsCreateDestination, "/admin/backups/destinations", "", sftpForm("loop", "127.0.0.1", true))
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Fatalf("loopback with opt-in accepted: %q", loc)
	}
}

// #148: destinations can be edited; an empty secret keeps the stored one and
// the edit form never sends secrets to the browser.
func TestBackupDestinationEdit(t *testing.T) {
	h, svc := backupEditHandlers(t)
	ctx := context.Background()
	id, err := svc.SaveDestination(ctx, backup.Destination{Name: "nas", Kind: "sftp", Enabled: true,
		Config: map[string]string{"host": "192.168.0.12", "user": "backup", "password": "s3cret-pass",
			"host_key": testHostKey, "path": "/volume1/hpg", "allow_private": "1"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	sid := jsonID(id)

	// Edit page: prefilled, secret absent from the HTML.
	req := httptest.NewRequest(http.MethodGet, "/admin/backups?edit="+sid, nil)
	req = req.WithContext(middleware.ContextWithSession(req.Context(), &auth.Session{UserID: 1, Role: "super_admin"}))
	page := httptest.NewRecorder()
	h.BackupsPage(page, req)
	body := page.Body.String()
	if !strings.Contains(body, `action="/admin/backups/destinations/`+sid+`"`) || !strings.Contains(body, `value="192.168.0.12"`) {
		t.Fatalf("edit form not prefilled (status %d)", page.Code)
	}
	if strings.Contains(body, "s3cret-pass") {
		t.Fatal("stored password leaked into the edit form")
	}
	if !strings.Contains(body, "unchanged - leave empty to keep") {
		t.Error("edit form does not say the password is kept")
	}

	// Change host + path, leave password empty, disable.
	f := sftpForm("nas-2", "192.168.0.13", true)
	f.Set("cfg_password", "")
	f.Set("cfg_path", "/volume2/hpg")
	rec := postBackupForm(h.BackupsUpdateDestination, "/admin/backups/destinations/"+sid, sid, f)
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "err=") {
		t.Fatalf("update refused: %q", loc)
	}
	got, err := svc.GetDestination(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "nas-2" || got.Enabled || got.Config["host"] != "192.168.0.13" ||
		got.Config["path"] != "/volume2/hpg" || got.Config["password"] != "s3cret-pass" {
		t.Fatalf("after update: name=%q enabled=%v cfg=%v", got.Name, got.Enabled, got.Config)
	}

	// Dropping the LAN opt-in on a private host is refused and changes nothing.
	f = sftpForm("nas-2", "192.168.0.13", false)
	f.Set("enabled", "1")
	rec = postBackupForm(h.BackupsUpdateDestination, "/admin/backups/destinations/"+sid, sid, f)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") || !strings.Contains(loc, "edit="+sid) {
		t.Fatalf("private host without opt-in on update: Location %q", loc)
	}
	if again, _ := svc.GetDestination(ctx, id); again.Enabled || again.Config["allow_private"] != "1" {
		t.Fatalf("refused update still wrote: %+v", again)
	}

	// Unknown id.
	rec = postBackupForm(h.BackupsUpdateDestination, "/admin/backups/destinations/999", "999", sftpForm("x", "192.168.0.13", true))
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Fatalf("missing destination updated: %q", loc)
	}
}
