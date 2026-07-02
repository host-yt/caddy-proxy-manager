// Package backup performs full control-plane backups: MariaDB schema+data
// dump, install_state.json, and the wg_config directory. The artifact is
// streamed into a tar.gz, optionally encrypted (AES-256-GCM, chunked,
// APP_SECRET-derived key via HKDF), and uploaded to a configured
// destination (SFTP / FTP(S) / S3-compatible / local filesystem).
//
// Restore is intentionally an operator action (not a panel button) to keep
// production blast radius small: pull the artifact, decrypt with the helper
// in cmd/backuprestore, replay the SQL, drop the state file in place,
// restart the panel.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
)

// Service orchestrates building + uploading backups. Single instance per app.
type Service struct {
	DB     func() *sql.DB
	State  *installstate.Manager
	Logger *slog.Logger

	// StateFilePath is the installstate.json on disk; included verbatim.
	StateFilePath string
	// WGConfigDir is the WireGuard config directory; included verbatim.
	WGConfigDir string

	// Webhooks is optional; when set, success/failure events fire on run.
	Webhooks WebhookEmitter
}

// WebhookEmitter is the minimal surface backup needs from internal/webhook.
type WebhookEmitter interface {
	Emit(ctx context.Context, eventType string, payload map[string]any)
}

// Destination kinds. Keep in sync with the SQL enum.
const (
	KindSFTP  = "sftp"
	KindFTP   = "ftp"
	KindS3    = "s3"
	KindLocal = "local"
)

// Destination is a configured backup target. Config is destination-specific
// (e.g. host/user/path for SFTP, bucket/region for S3); persisted encrypted
// in backup_destinations.config_enc.
type Destination struct {
	ID        int64
	Name      string
	Kind      string
	Enabled   bool
	Config    map[string]string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Job is a single backup run.
type Job struct {
	ID            int64
	DestinationID int64
	Kind          string // "manual" | "scheduled"
	Status        string // pending | running | succeeded | failed
	ArtifactKey   string
	SizeBytes     int64
	SHA256        string
	Encrypted     bool
	StartedAt     time.Time
	FinishedAt    time.Time
	ErrorText     string
	TriggeredBy   int64
	CreatedAt     time.Time
}

// LoadDestinations reads all backup destinations from DB and decrypts
// their config JSON via installstate.Manager.
func (s *Service) LoadDestinations(ctx context.Context, onlyEnabled bool) ([]Destination, error) {
	db := s.DB()
	if db == nil {
		return nil, errors.New("db not ready")
	}
	q := "SELECT id, name, kind, config_enc, is_enabled, created_at, updated_at FROM backup_destinations"
	if onlyEnabled {
		q += " WHERE is_enabled = 1"
	}
	q += " ORDER BY id ASC"
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Destination
	for rows.Next() {
		var d Destination
		var enc string
		var enabled int
		if err := rows.Scan(&d.ID, &d.Name, &d.Kind, &enc, &enabled, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		d.Enabled = enabled == 1
		cfg, err := s.decodeConfig(enc)
		if err != nil {
			s.Logger.Warn("backup: decode destination config", "id", d.ID, "err", err)
			continue
		}
		d.Config = cfg
		out = append(out, d)
	}
	return out, nil
}

// GetDestination fetches one destination by id.
func (s *Service) GetDestination(ctx context.Context, id int64) (Destination, error) {
	db := s.DB()
	if db == nil {
		return Destination{}, errors.New("db not ready")
	}
	var d Destination
	var enc string
	var enabled int
	err := db.QueryRowContext(ctx,
		"SELECT id, name, kind, config_enc, is_enabled, created_at, updated_at FROM backup_destinations WHERE id = ?",
		id,
	).Scan(&d.ID, &d.Name, &d.Kind, &enc, &enabled, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return Destination{}, err
	}
	d.Enabled = enabled == 1
	d.Config, err = s.decodeConfig(enc)
	if err != nil {
		return Destination{}, err
	}
	return d, nil
}

// SaveDestination inserts a new destination row (no update path — admin
// deletes and re-creates to rotate credentials).
func (s *Service) SaveDestination(ctx context.Context, d Destination, createdBy int64) (int64, error) {
	db := s.DB()
	if db == nil {
		return 0, errors.New("db not ready")
	}
	if d.Name == "" {
		return 0, errors.New("name required")
	}
	if !validKind(d.Kind) {
		return 0, fmt.Errorf("invalid kind: %s", d.Kind)
	}
	enc, err := s.encodeConfig(d.Config)
	if err != nil {
		return 0, err
	}
	var createdByVal sql.NullInt64
	if createdBy != 0 {
		createdByVal = sql.NullInt64{Int64: createdBy, Valid: true}
	}
	enabled := 1
	if !d.Enabled {
		enabled = 0
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO backup_destinations (name, kind, config_enc, is_enabled, created_by)
		 VALUES (?, ?, ?, ?, ?)`,
		d.Name, d.Kind, enc, enabled, createdByVal)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// DeleteDestination removes a destination. Existing job rows cascade.
func (s *Service) DeleteDestination(ctx context.Context, id int64) error {
	db := s.DB()
	if db == nil {
		return errors.New("db not ready")
	}
	_, err := db.ExecContext(ctx, "DELETE FROM backup_destinations WHERE id = ?", id)
	return err
}

// RecentJobs returns the last `limit` job rows for the admin UI.
func (s *Service) RecentJobs(ctx context.Context, limit int) ([]Job, error) {
	db := s.DB()
	if db == nil {
		return nil, errors.New("db not ready")
	}
	if limit <= 0 {
		limit = 25
	}
	rows, err := db.QueryContext(ctx,
		`SELECT j.id, j.destination_id, j.kind, j.status, COALESCE(j.artifact_key,''),
		        j.size_bytes, COALESCE(j.sha256,''), j.encrypted,
		        j.started_at, j.finished_at, COALESCE(j.error_text,''),
		        COALESCE(j.triggered_by,0), j.created_at
		 FROM backup_jobs j ORDER BY j.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		var j Job
		var enc int
		var started, finished sql.NullTime
		if err := rows.Scan(&j.ID, &j.DestinationID, &j.Kind, &j.Status, &j.ArtifactKey,
			&j.SizeBytes, &j.SHA256, &enc, &started, &finished, &j.ErrorText,
			&j.TriggeredBy, &j.CreatedAt); err != nil {
			return nil, err
		}
		j.Encrypted = enc == 1
		if started.Valid {
			j.StartedAt = started.Time
		}
		if finished.Valid {
			j.FinishedAt = finished.Time
		}
		out = append(out, j)
	}
	return out, nil
}

// RunOptions controls a single backup invocation.
type RunOptions struct {
	DestinationID int64
	Kind          string // "manual" | "scheduled"
	TriggeredBy   int64
	Encrypt       bool
}

// Run executes a full backup against the given destination. Returns the
// job row id.
func (s *Service) Run(ctx context.Context, o RunOptions) (int64, error) {
	if o.Kind == "" {
		o.Kind = "manual"
	}
	dest, err := s.GetDestination(ctx, o.DestinationID)
	if err != nil {
		return 0, fmt.Errorf("load destination: %w", err)
	}
	if !dest.Enabled {
		return 0, errors.New("destination disabled")
	}

	// Fail-safe: the artifact bundles the full DB dump, install_state.json
	// and WG private keys, so it must never leave the host in cleartext.
	// Force encryption for any non-local destination regardless of the
	// caller's toggle (security review SECRET-01). A local on-host target
	// may stay plaintext.
	if !o.Encrypt && dest.Kind != KindLocal {
		if s.State == nil {
			return 0, fmt.Errorf("refusing unencrypted backup to %s destination %q: encryption unavailable (installstate not wired)", dest.Kind, dest.Name)
		}
		s.Logger.Warn("backup: forcing encryption for remote destination", "dest", dest.Name, "kind", dest.Kind)
		o.Encrypt = true
	}

	db := s.DB()
	if db == nil {
		return 0, errors.New("db not ready")
	}

	var triggeredBy sql.NullInt64
	if o.TriggeredBy != 0 {
		triggeredBy = sql.NullInt64{Int64: o.TriggeredBy, Valid: true}
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO backup_jobs (destination_id, kind, status, encrypted, triggered_by, started_at)
		 VALUES (?, ?, 'running', ?, ?, NOW())`,
		dest.ID, o.Kind, boolToInt(o.Encrypt), triggeredBy)
	if err != nil {
		return 0, err
	}
	jobID, _ := res.LastInsertId()

	finish := func(status, errText, artifactKey, sum string, size int64) {
		_, _ = db.ExecContext(context.Background(),
			`UPDATE backup_jobs SET status=?, error_text=?, artifact_key=?, sha256=?,
			 size_bytes=?, finished_at=NOW() WHERE id=?`,
			status, errText, artifactKey, sum, size, jobID)
	}

	artifactKey, size, sum, err := s.runOnce(ctx, dest, jobID, o.Encrypt)
	if err != nil {
		s.Logger.Error("backup: run failed", "job_id", jobID, "dest", dest.Name, "err", err)
		finish("failed", truncateErr(err.Error()), artifactKey, sum, size)
		if s.Webhooks != nil {
			s.Webhooks.Emit(ctx, "backup.failed", map[string]any{
				"job_id": jobID, "destination": dest.Name, "kind": dest.Kind, "error": truncateErr(err.Error()),
			})
		}
		return jobID, err
	}
	finish("succeeded", "", artifactKey, sum, size)
	s.Logger.Info("backup: ok", "job_id", jobID, "dest", dest.Name, "size", size, "encrypted", o.Encrypt)
	if s.Webhooks != nil {
		s.Webhooks.Emit(ctx, "backup.success", map[string]any{
			"job_id": jobID, "destination": dest.Name, "kind": dest.Kind,
			"size_bytes": size, "sha256": sum, "artifact_key": artifactKey,
		})
	}
	return jobID, nil
}

// runOnce builds the artifact and uploads it.
func (s *Service) runOnce(ctx context.Context, dest Destination, jobID int64, encrypt bool) (artifactKey string, size int64, sum string, err error) {
	// Build artifact into a temp file (streaming; supports >RAM backups).
	tmp, err := os.CreateTemp("", "hpg-backup-*.tgz")
	if err != nil {
		return "", 0, "", fmt.Errorf("temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	hasher := sha256.New()
	mw := io.MultiWriter(tmp, hasher)

	if encrypt {
		if s.State == nil {
			return "", 0, "", errors.New("encryption requested but installstate not wired")
		}
		key, err := s.State.DeriveBackupKey()
		if err != nil {
			return "", 0, "", fmt.Errorf("derive key: %w", err)
		}
		ew, err := newStreamEncryptWriter(mw, key)
		if err != nil {
			return "", 0, "", fmt.Errorf("stream encrypt: %w", err)
		}
		if err := s.writeArchive(ctx, ew); err != nil {
			return "", 0, "", err
		}
		if err := ew.Close(); err != nil {
			return "", 0, "", fmt.Errorf("close stream: %w", err)
		}
	} else {
		if err := s.writeArchive(ctx, mw); err != nil {
			return "", 0, "", err
		}
	}

	if err := tmp.Sync(); err != nil {
		return "", 0, "", err
	}
	st, err := tmp.Stat()
	if err != nil {
		return "", 0, "", err
	}
	size = st.Size()
	sum = hex.EncodeToString(hasher.Sum(nil))

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return "", size, sum, err
	}

	// Upload. Key includes job id for traceability.
	suffix := ".tgz"
	if encrypt {
		suffix = ".tgz.age"
	}
	artifactKey = fmt.Sprintf("hpg-%s-job-%d%s",
		time.Now().UTC().Format("20060102-150405"), jobID, suffix)

	uploader, err := newDestination(dest)
	if err != nil {
		return artifactKey, size, sum, fmt.Errorf("destination: %w", err)
	}
	if err := uploader.Upload(ctx, artifactKey, tmp, size); err != nil {
		return artifactKey, size, sum, fmt.Errorf("upload: %w", err)
	}
	return artifactKey, size, sum, nil
}

// writeArchive emits a tar.gz with: dump.sql, install_state.json (if
// present), wg/<files> (if present). The caller is responsible for any
// outer encryption.
func (s *Service) writeArchive(ctx context.Context, w io.Writer) error {
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	// 1) DB dump.
	dumpBuf := newCountingBuffer()
	if err := DumpDatabase(ctx, s.DB(), dumpBuf); err != nil {
		return fmt.Errorf("dump: %w", err)
	}
	hdr := &tar.Header{
		Name:    "dump.sql",
		Mode:    0o600,
		Size:    int64(dumpBuf.Len()),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := dumpBuf.WriteTo(tw); err != nil {
		return err
	}

	// 2) install_state.json (if exists).
	if s.StateFilePath != "" {
		if data, err := os.ReadFile(s.StateFilePath); err == nil {
			h := &tar.Header{Name: "install_state.json", Mode: 0o600, Size: int64(len(data)), ModTime: time.Now().UTC()}
			if err := tw.WriteHeader(h); err != nil {
				return err
			}
			if _, err := tw.Write(data); err != nil {
				return err
			}
		}
	}

	// 3) wg_config directory (if exists).
	if s.WGConfigDir != "" {
		entries, err := os.ReadDir(s.WGConfigDir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
					continue
				}
				p := filepath.Join(s.WGConfigDir, e.Name())
				data, rerr := os.ReadFile(p)
				if rerr != nil {
					continue
				}
				h := &tar.Header{Name: "wg/" + e.Name(), Mode: 0o600, Size: int64(len(data)), ModTime: time.Now().UTC()}
				if err := tw.WriteHeader(h); err != nil {
					return err
				}
				if _, err := tw.Write(data); err != nil {
					return err
				}
			}
		}
	}

	// 4) manifest (small JSON with versions / counts).
	manifest, _ := json.Marshal(map[string]any{
		"created_at":    time.Now().UTC().Format(time.RFC3339),
		"hpg_version":   "1",
		"contents":      []string{"dump.sql", "install_state.json", "wg/*"},
		"db_dump_bytes": dumpBuf.Len(),
	})
	h := &tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(manifest)), ModTime: time.Now().UTC()}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	if _, err := tw.Write(manifest); err != nil {
		return err
	}
	return nil
}

// encodeConfig encrypts a config map to a base64 blob in the settings
// envelope.
func (s *Service) encodeConfig(cfg map[string]string) (string, error) {
	if cfg == nil {
		cfg = map[string]string{}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	if s.State == nil {
		// Fail closed: never persist destination credentials (S3 keys, SFTP
		// passwords, SSH keys) in cleartext. The read path still accepts legacy
		// plain:/unprefixed blobs, but we refuse to write new ones (SECRET-03).
		return "", errors.New("cannot encrypt destination config: installstate not wired")
	}
	enc, err := s.State.Encrypt(string(raw))
	if err != nil {
		return "", err
	}
	return "enc:" + enc, nil
}

func (s *Service) decodeConfig(stored string) (map[string]string, error) {
	cfg := map[string]string{}
	switch {
	case strings.HasPrefix(stored, "enc:"):
		if s.State == nil {
			return cfg, errors.New("encrypted config but no installstate")
		}
		pt, err := s.State.Decrypt(strings.TrimPrefix(stored, "enc:"))
		if err != nil {
			return cfg, err
		}
		if err := json.Unmarshal([]byte(pt), &cfg); err != nil {
			return cfg, err
		}
	case strings.HasPrefix(stored, "plain:"):
		if err := json.Unmarshal([]byte(strings.TrimPrefix(stored, "plain:")), &cfg); err != nil {
			return cfg, err
		}
	default:
		// Legacy / unprefixed: try JSON.
		if err := json.Unmarshal([]byte(stored), &cfg); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

// Test runs a connectivity check against a destination by writing a tiny
// probe file and removing it. Surfaces auth + path errors before the first
// real backup.
func (s *Service) Test(ctx context.Context, dest Destination) error {
	u, err := newDestination(dest)
	if err != nil {
		return err
	}
	probe := fmt.Sprintf("hpg-probe-%d.txt", time.Now().UnixNano())
	body := []byte("hostyt-proxy-gateway connectivity probe " + time.Now().UTC().Format(time.RFC3339))
	r := newSeekingReader(body)
	if err := u.Upload(ctx, probe, r, int64(len(body))); err != nil {
		return fmt.Errorf("probe upload: %w", err)
	}
	_ = u.Delete(ctx, probe)
	return nil
}

func validKind(k string) bool {
	switch k {
	case KindSFTP, KindFTP, KindS3, KindLocal:
		return true
	}
	return false
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func truncateErr(s string) string {
	const max = 4000
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
