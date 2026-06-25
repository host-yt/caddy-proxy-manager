// Package jobs contains standalone background jobs that don't belong in a
// domain package.
package jobs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/hostyt/proxy-gateway/internal/backup"
	"github.com/hostyt/proxy-gateway/internal/installstate"
)

const drillDefaultInterval = 72 * time.Hour

// coreTables that must exist in the restored schema to pass the drill.
var coreTables = []string{"settings", "users", "routes", "caddy_nodes", "clients"}

const minTableCount = 5

// BackupDrillJob periodically restores the latest backup SQL into a throwaway
// schema (hpg_drill_YYYYMMDD), verifies core tables, drops it, and records
// the result in the settings table.
type BackupDrillJob struct {
	// DB returns the live pool (func, not *sql.DB, because pool may not be ready at wiring time).
	DB func() *sql.DB
	// State is used to decrypt the DB password and the backup encryption key.
	State *installstate.Manager
	// Logger for structured output.
	Logger *slog.Logger
	// Interval between runs; 0 uses the 72 h default.
	Interval time.Duration
}

func (j *BackupDrillJob) interval() time.Duration {
	if j.Interval > 0 {
		return j.Interval
	}
	return drillDefaultInterval
}

// Run blocks until ctx is cancelled, firing a drill on each interval tick.
func (j *BackupDrillJob) Run(ctx context.Context) {
	t := time.NewTimer(j.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		j.tick(ctx)
		t.Reset(j.interval())
	}
}

func (j *BackupDrillJob) tick(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			j.Logger.Error("backup-drill: panic", "panic", r)
		}
	}()
	if err := j.runDrill(ctx); err != nil {
		j.Logger.Error("backup-drill: failed", "err", err)
		j.writeResult(ctx, "failed: "+drillTruncate(err.Error(), 200))
		return
	}
	j.Logger.Info("backup-drill: ok")
	j.writeResult(ctx, "ok")
}

func (j *BackupDrillJob) runDrill(ctx context.Context) error {
	db := j.DB()
	if db == nil {
		return errors.New("db not ready")
	}

	// 1. Find latest succeeded backup job with an artifact.
	var jobID, destID int64
	var artifactKey string
	var encInt int
	err := db.QueryRowContext(ctx,
		`SELECT id, destination_id, artifact_key, encrypted
		 FROM backup_jobs
		 WHERE status = 'succeeded' AND artifact_key <> ''
		 ORDER BY id DESC LIMIT 1`,
	).Scan(&jobID, &destID, &artifactKey, &encInt)
	if err != nil {
		return fmt.Errorf("no succeeded backup found: %w", err)
	}
	encrypted := encInt == 1
	j.Logger.Info("backup-drill: using backup", "job_id", jobID, "artifact", artifactKey)

	// 2. Load destination (GetDestination decrypts config for us).
	svc := &backup.Service{DB: j.DB, State: j.State, Logger: j.Logger}
	dest, err := svc.GetDestination(ctx, destID)
	if err != nil {
		return fmt.Errorf("load destination: %w", err)
	}
	if dest.Kind != backup.KindLocal {
		j.Logger.Warn("backup-drill: skipped — drill only supports 'local' destinations",
			"kind", dest.Kind)
		return fmt.Errorf("drill not implemented for destination kind %q (only 'local' supported)", dest.Kind)
	}

	// 3. Read artifact from local filesystem (cap at 500 MB to avoid OOM).
	root := strings.TrimSpace(dest.Config["path"])
	if root == "" {
		return errors.New("local destination path not configured")
	}
	artifactPath := filepath.Join(root, artifactKey)
	const maxArtifactBytes = 500 << 20
	fi, err := os.Stat(artifactPath)
	if err != nil {
		return fmt.Errorf("stat artifact %s: %w", artifactPath, err)
	}
	if fi.Size() > maxArtifactBytes {
		return fmt.Errorf("artifact %s too large (%d bytes; limit %d)", artifactPath, fi.Size(), maxArtifactBytes)
	}
	raw, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("read artifact %s: %w", artifactPath, err)
	}

	// 4. Decrypt if needed.
	src := io.Reader(bytes.NewReader(raw))
	if encrypted {
		if j.State == nil {
			return errors.New("encrypted artifact but State not wired")
		}
		key, err := j.State.DeriveBackupKey()
		if err != nil {
			return fmt.Errorf("derive backup key: %w", err)
		}
		var dec bytes.Buffer
		if err := backup.StreamDecrypt(bytes.NewReader(raw), &dec, key); err != nil {
			return fmt.Errorf("decrypt artifact: %w", err)
		}
		src = &dec
	}

	// 5. Extract dump.sql from tar.gz.
	dumpSQL, err := extractDumpSQL(src)
	if err != nil {
		return fmt.Errorf("extract dump.sql: %w", err)
	}

	// 6. Open side-connection to the same MariaDB server, targeting the drill schema.
	// Use full timestamp so re-runs on the same day get a fresh empty schema.
	drillSchema := "hpg_drill_" + time.Now().UTC().Format("20060102_150405")
	drillDSN, err := j.drillDSN(drillSchema)
	if err != nil {
		return fmt.Errorf("build drill dsn: %w", err)
	}
	drillDB, err := sql.Open("mysql", drillDSN)
	if err != nil {
		return fmt.Errorf("open drill db: %w", err)
	}
	defer drillDB.Close()
	drillDB.SetMaxOpenConns(1)
	drillDB.SetConnMaxLifetime(5 * time.Minute)

	// 7. Create temp schema — fail gracefully if the DB user lacks CREATE privilege.
	if _, err := drillDB.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS `"+drillSchema+"`"); err != nil {
		return fmt.Errorf("CREATE DATABASE %s: %w (ensure DB user has CREATE privilege)", drillSchema, err)
	}
	j.Logger.Debug("backup-drill: schema created", "schema", drillSchema)

	defer func() {
		dropCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := drillDB.ExecContext(dropCtx, "DROP DATABASE IF EXISTS `"+drillSchema+"`"); err != nil {
			j.Logger.Warn("backup-drill: DROP schema failed", "schema", drillSchema, "err", err)
		} else {
			j.Logger.Debug("backup-drill: schema dropped", "schema", drillSchema)
		}
	}()

	// 8. Replay dump.
	restoreCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	j.replaySQL(restoreCtx, drillDB, dumpSQL)

	// 9. Verify core tables — use restoreCtx so it doesn't time out after replay.
	found, err := j.countCoreTables(restoreCtx, drillDB)
	if err != nil {
		return fmt.Errorf("verify tables: %w", err)
	}
	if found < minTableCount {
		return fmt.Errorf("only %d/%d core tables present after restore", found, minTableCount)
	}
	j.Logger.Info("backup-drill: tables verified", "found", found, "required", minTableCount)
	return nil
}

// maxDumpSQLBytes caps the decompressed dump.sql to prevent OOM when a
// highly-compressible artifact decompresses to many GB.
const maxDumpSQLBytes = 2 << 30 // 2 GB

// extractDumpSQL walks the tar.gz stream and returns the dump.sql file contents.
func extractDumpSQL(src io.Reader) (string, error) {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return "", fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("tar: %w", err)
		}
		if hdr.Name == "dump.sql" {
			limited := io.LimitReader(tr, maxDumpSQLBytes+1)
			data, err := io.ReadAll(limited)
			if err != nil {
				return "", fmt.Errorf("read dump.sql: %w", err)
			}
			if int64(len(data)) > maxDumpSQLBytes {
				return "", fmt.Errorf("dump.sql exceeds %d byte limit", maxDumpSQLBytes)
			}
			return string(data), nil
		}
	}
	return "", errors.New("dump.sql not found in archive")
}

// replaySQL replays dump statements into the drill DB. Statement errors are
// logged but non-fatal — the table-count verify step catches real failures.
// Statements that could affect the production server (USE, DROP DATABASE,
// GRANT, CREATE/DROP USER, REVOKE) are skipped entirely.
func (j *BackupDrillJob) replaySQL(ctx context.Context, db *sql.DB, dump string) {
	stmts := strings.Split(dump, ";\n")
	for _, stmt := range stmts {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || strings.HasPrefix(stmt, "--") {
			continue
		}
		if isDangerousSQL(stmt) {
			j.Logger.Debug("backup-drill: skipping dangerous stmt", "stmt_prefix", drillTruncate(stmt, 80))
			continue
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			j.Logger.Debug("backup-drill: stmt error (non-fatal)",
				"err", err, "stmt_prefix", drillTruncate(stmt, 80))
		}
	}
}

// isDangerousSQL reports whether a SQL statement should never execute in the
// drill context because it could affect the production server or grant
// privileges. Comparison is case-insensitive on the first token.
func isDangerousSQL(stmt string) bool {
	upper := strings.ToUpper(strings.TrimSpace(stmt))
	for _, prefix := range []string{
		"USE ", "USE\t",
		"DROP DATABASE", "DROP SCHEMA",
		"GRANT ", "REVOKE ",
		"CREATE USER", "DROP USER", "ALTER USER", "RENAME USER",
	} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// countCoreTables counts how many of coreTables exist in the drill schema.
func (j *BackupDrillJob) countCoreTables(ctx context.Context, db *sql.DB) (int, error) {
	found := 0
	for _, t := range coreTables {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM information_schema.tables
			 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?`, t,
		).Scan(&n); err != nil {
			return found, err
		}
		if n > 0 {
			found++
		}
	}
	return found, nil
}

// drillDSN builds a DSN for the drill schema using the same MariaDB server as production.
func (j *BackupDrillJob) drillDSN(schema string) (string, error) {
	if j.State == nil {
		return "", errors.New("installstate not wired")
	}
	s := j.State.Get()
	if s.DB == nil {
		return "", errors.New("db state not in installstate")
	}
	pw, err := j.State.Decrypt(s.DB.PasswordCipher)
	if err != nil {
		return "", fmt.Errorf("decrypt db password: %w", err)
	}
	tls := ""
	if s.DB.TLS {
		tls = "&tls=true"
	}
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC&charset=utf8mb4%s",
		s.DB.User, pw, s.DB.Host, s.DB.Port, schema, tls,
	), nil
}

// writeResult upserts drill outcome into the settings table.
func (j *BackupDrillJob) writeResult(ctx context.Context, status string) {
	db := j.DB()
	if db == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	upsert := func(key, val string) {
		if _, err := db.ExecContext(ctx,
			"INSERT INTO settings (`key`, value, is_encrypted) VALUES (?, ?, 0) "+
				"ON DUPLICATE KEY UPDATE value=VALUES(value)",
			key, val,
		); err != nil {
			j.Logger.Warn("backup-drill: write setting", "key", key, "err", err)
		}
	}
	upsert("backup_last_drill_at", now)
	upsert("backup_last_drill_status", status)
}

func drillTruncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
