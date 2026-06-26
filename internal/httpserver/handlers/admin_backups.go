package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/backup"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// Backups page + actions live on AdminHandlers; the field is wired from main.go.

type backupsViewData struct {
	baseAdminData
	Destinations []backupDestRow
	Jobs         []backupJobRow
	Schedule     backupScheduleRow
	NewKindOpts  []string
}

type backupDestRow struct {
	ID      int64
	Name    string
	Kind    string
	Enabled bool
	Summary string
}

type backupJobRow struct {
	ID          int64
	DestName    string
	Kind        string
	Status      string
	SizeKB      int64
	Encrypted   bool
	StartedAt   string
	FinishedAt  string
	Error       string
	ArtifactKey string
}

type backupScheduleRow struct {
	IntervalHours int
	RetentionDays int
	EncryptByDef  bool
}

// BackupsPage GET /admin/backups.
func (h *AdminHandlers) BackupsPage(w http.ResponseWriter, r *http.Request) {
	if h.Backups == nil {
		http.Error(w, "backup service not wired", http.StatusServiceUnavailable)
		return
	}
	d := backupsViewData{
		baseAdminData: h.base(r, "Backups"),
		NewKindOpts:   []string{backup.KindSFTP, backup.KindFTP, backup.KindS3, backup.KindLocal},
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if dests, err := h.Backups.LoadDestinations(ctx, false); err == nil {
		for _, ds := range dests {
			d.Destinations = append(d.Destinations, backupDestRow{
				ID: ds.ID, Name: ds.Name, Kind: ds.Kind, Enabled: ds.Enabled,
				Summary: backupDestSummary(ds),
			})
		}
	}
	if jobs, err := h.Backups.RecentJobs(ctx, 25); err == nil {
		nameByID := map[int64]string{}
		for _, ds := range d.Destinations {
			nameByID[ds.ID] = ds.Name
		}
		for _, j := range jobs {
			row := backupJobRow{
				ID: j.ID, DestName: nameByID[j.DestinationID], Kind: j.Kind, Status: j.Status,
				SizeKB: j.SizeBytes / 1024, Encrypted: j.Encrypted, Error: j.ErrorText,
				ArtifactKey: j.ArtifactKey,
			}
			if !j.StartedAt.IsZero() {
				row.StartedAt = j.StartedAt.Format(time.RFC3339)
			}
			if !j.FinishedAt.IsZero() {
				row.FinishedAt = j.FinishedAt.Format(time.RFC3339)
			}
			d.Jobs = append(d.Jobs, row)
		}
	}
	d.Schedule = h.loadBackupSchedule(ctx)
	h.render(w, "backups", d)
}

func backupDestSummary(d backup.Destination) string {
	switch d.Kind {
	case backup.KindSFTP:
		return d.Config["user"] + "@" + d.Config["host"] + ":" + d.Config["path"]
	case backup.KindFTP:
		return d.Config["user"] + "@" + d.Config["host"] + " " + d.Config["path"]
	case backup.KindS3:
		return d.Config["endpoint"] + "/" + d.Config["bucket"]
	case backup.KindLocal:
		return d.Config["path"]
	}
	return d.Kind
}

func (h *AdminHandlers) loadBackupSchedule(ctx context.Context) backupScheduleRow {
	row := backupScheduleRow{EncryptByDef: true}
	db := h.DB()
	if db == nil {
		return row
	}
	get := func(key string) string {
		var v string
		_ = db.QueryRowContext(ctx, "SELECT value FROM settings WHERE `key` = ?", key).Scan(&v)
		return v
	}
	if n, err := strconv.Atoi(strings.TrimSpace(get("backup.schedule_interval_hours"))); err == nil {
		row.IntervalHours = n
	}
	if n, err := strconv.Atoi(strings.TrimSpace(get("backup.retention_days"))); err == nil {
		row.RetentionDays = n
	}
	if v := get("backup.encrypt"); v == "0" {
		row.EncryptByDef = false
	}
	return row
}

// BackupsCreateDestination POST /admin/backups/destinations.
func (h *AdminHandlers) BackupsCreateDestination(w http.ResponseWriter, r *http.Request) {
	if h.Backups == nil {
		http.Error(w, "backup service not wired", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	kind := strings.TrimSpace(r.FormValue("kind"))
	if name == "" || kind == "" {
		redirectWithFlash(w, r, "/admin/backups", "", "name + kind required")
		return
	}
	cfg := map[string]string{}
	// Copy all "cfg_*" form fields into the config map (UI controls naming).
	for k, vs := range r.PostForm {
		if !strings.HasPrefix(k, "cfg_") || len(vs) == 0 {
			continue
		}
		cfg[strings.TrimPrefix(k, "cfg_")] = vs[0]
	}
	d := backup.Destination{Name: name, Kind: kind, Enabled: true, Config: cfg}
	sess := middleware.SessionFromContext(r.Context())
	var uid int64
	if sess != nil {
		uid = sess.UserID
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	id, err := h.Backups.SaveDestination(ctx, d, uid)
	if err != nil {
		redirectWithFlash(w, r, "/admin/backups", "", "save failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, Action: "backup.destination.create", Entity: "backup_destination",
		EntityID: strconv.FormatInt(id, 10),
		Meta:     map[string]any{"name": name, "kind": kind},
	})
	redirectWithFlash(w, r, "/admin/backups", "destination saved", "")
}

// BackupsDeleteDestination POST /admin/backups/destinations/{id}/delete.
func (h *AdminHandlers) BackupsDeleteDestination(w http.ResponseWriter, r *http.Request) {
	if h.Backups == nil {
		http.Error(w, "backup service not wired", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if id == 0 {
		redirectWithFlash(w, r, "/admin/backups", "", "bad id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.Backups.DeleteDestination(ctx, id); err != nil {
		redirectWithFlash(w, r, "/admin/backups", "", "delete failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	var uid int64
	if sess != nil {
		uid = sess.UserID
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, Action: "backup.destination.delete", Entity: "backup_destination",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, "/admin/backups", "destination removed", "")
}

// BackupsVerify POST /admin/backups/destinations/{id}/verify.
// Downloads the most recent successful artifact, verifies sha256/size,
// decrypts it, and walks the tar to assert dump.sql is present. Records
// a new backup_jobs row of kind='manual' with the outcome.
func (h *AdminHandlers) BackupsVerify(w http.ResponseWriter, r *http.Request) {
	if h.Backups == nil {
		http.Error(w, "backup service not wired", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if err := h.Backups.Verify(ctx, id); err != nil {
		redirectWithFlash(w, r, "/admin/backups", "", "verify failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	var uid int64
	if sess != nil {
		uid = sess.UserID
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, Action: "backup.verify", Entity: "backup_destination",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, "/admin/backups", "verify OK", "")
}

// BackupsTestDestination POST /admin/backups/destinations/{id}/test.
func (h *AdminHandlers) BackupsTestDestination(w http.ResponseWriter, r *http.Request) {
	if h.Backups == nil {
		http.Error(w, "backup service not wired", http.StatusServiceUnavailable)
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	dest, err := h.Backups.GetDestination(ctx, id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/backups", "", "load failed: "+sanitizeErr(err))
		return
	}
	if err := h.Backups.Test(ctx, dest); err != nil {
		redirectWithFlash(w, r, "/admin/backups", "", "test failed: "+sanitizeErr(err))
		return
	}
	redirectWithFlash(w, r, "/admin/backups", "connectivity OK", "")
}

// BackupsRunNow POST /admin/backups/run-now.
func (h *AdminHandlers) BackupsRunNow(w http.ResponseWriter, r *http.Request) {
	if h.Backups == nil {
		http.Error(w, "backup service not wired", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	destID, _ := strconv.ParseInt(r.FormValue("destination_id"), 10, 64)
	encrypt := r.FormValue("encrypt") != "0"
	sess := middleware.SessionFromContext(r.Context())
	var uid int64
	if sess != nil {
		uid = sess.UserID
	}
	// Run in background; the UI polls.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if _, err := h.Backups.Run(ctx, backup.RunOptions{
			DestinationID: destID, Kind: "manual", TriggeredBy: uid, Encrypt: encrypt,
		}); err != nil {
			h.Logger.Warn("backup run-now failed", "dest_id", destID, "err", err)
		}
	}()
	audit.Write(r.Context(), h.DB(), h.Logger, r, audit.Entry{
		UserID: &uid, Action: "backup.run", Entity: "backup_destination",
		EntityID: strconv.FormatInt(destID, 10),
		Meta:     map[string]any{"encrypt": encrypt},
	})
	redirectWithFlash(w, r, "/admin/backups", "backup started", "")
}

// BackupsSaveSchedule POST /admin/backups/schedule.
func (h *AdminHandlers) BackupsSaveSchedule(w http.ResponseWriter, r *http.Request) {
	if h.Backups == nil {
		http.Error(w, "backup service not wired", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	intervalH, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("interval_hours")))
	retentionD, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("retention_days")))
	encrypt := r.FormValue("encrypt") != "0"
	if intervalH < 0 {
		intervalH = 0
	}
	if retentionD < 0 {
		retentionD = 0
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	db := h.DB()
	if db == nil {
		http.Error(w, "db not ready", http.StatusServiceUnavailable)
		return
	}
	set := func(k, v string) {
		_, _ = db.ExecContext(ctx,
			"INSERT INTO settings (`key`, value, is_encrypted) VALUES (?, ?, 0) ON DUPLICATE KEY UPDATE value=VALUES(value)",
			k, v)
	}
	set("backup.schedule_interval_hours", strconv.Itoa(intervalH))
	set("backup.retention_days", strconv.Itoa(retentionD))
	encVal := "1"
	if !encrypt {
		encVal = "0"
	}
	set("backup.encrypt", encVal)
	sess := middleware.SessionFromContext(r.Context())
	var uid int64
	if sess != nil {
		uid = sess.UserID
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: &uid, Action: "backup.schedule.update", Entity: "settings",
		Meta: map[string]any{"interval_hours": intervalH, "retention_days": retentionD, "encrypt": encrypt},
	})
	redirectWithFlash(w, r, "/admin/backups", "schedule saved", "")
}
