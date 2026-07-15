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
	"sync"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/backup"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
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

// advisoryLockName is the MySQL advisory lock name used to serialize drills cluster-wide.
const advisoryLockName = "hpg_restore_drill"

// drillMu serializes restore drills on SQLite (single-process, no advisory lock available).
var drillMu sync.Mutex

// acquireAdvisoryLock tries to acquire a drill lock.
// For SQLite: uses package mutex (returns conn=nil on success).
// For MySQL: uses GET_LOCK on a dedicated connection.
// Returns nil, false if the lock is held or on any error.
func (j *BackupDrillJob) acquireAdvisoryLock(ctx context.Context) (*sql.Conn, bool) {
	if store.Driver() == "sqlite3" {
		if !drillMu.TryLock() {
			j.Logger.Info("backup-drill: advisory lock already held, skipping run")
			return nil, false
		}
		return nil, true // conn=nil signals SQLite path to releaseAdvisoryLock
	}
	db := j.DB()
	if db == nil {
		return nil, false
	}
	// GET_LOCK/RELEASE_LOCK must run on the same physical connection.
	conn, err := db.Conn(ctx)
	if err != nil {
		j.Logger.Warn("backup-drill: advisory lock: get conn", "err", err)
		return nil, false
	}
	var result sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 0)", advisoryLockName).Scan(&result); err != nil {
		j.Logger.Warn("backup-drill: advisory lock: GET_LOCK error", "err", err)
		_ = conn.Close()
		return nil, false
	}
	if !result.Valid || result.Int64 != 1 {
		j.Logger.Info("backup-drill: advisory lock already held, skipping run")
		_ = conn.Close()
		return nil, false
	}
	return conn, true
}

// releaseAdvisoryLock releases the drill lock.
// For SQLite (conn==nil): releases the package mutex.
// For MySQL: releases GET_LOCK and closes the connection.
func (j *BackupDrillJob) releaseAdvisoryLock(conn *sql.Conn) {
	if conn == nil {
		// SQLite path: release package mutex.
		drillMu.Unlock()
		return
	}
	releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.ExecContext(releaseCtx, "SELECT RELEASE_LOCK(?)", advisoryLockName); err != nil {
		j.Logger.Warn("backup-drill: advisory lock: RELEASE_LOCK error", "err", err)
	}
	_ = conn.Close()
}

// RunOnce executes a single drill immediately; used for manual UI triggers.
func (j *BackupDrillJob) RunOnce(ctx context.Context) {
	// Advisory lock serializes against scheduled runs and other replicas.
	conn, ok := j.acquireAdvisoryLock(ctx)
	if !ok {
		return
	}
	defer j.releaseAdvisoryLock(conn)
	j.tick(ctx)
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
		// Advisory lock ensures only one replica runs at a time.
		if conn, ok := j.acquireAdvisoryLock(ctx); ok {
			j.tick(ctx)
			j.releaseAdvisoryLock(conn)
		}
		t.Reset(j.interval())
	}
}

func (j *BackupDrillJob) tick(ctx context.Context) {
	started := time.Now().UTC()
	defer func() {
		if r := recover(); r != nil {
			j.Logger.Error("backup-drill: panic", "panic", r)
		}
	}()
	rows, err := j.runDrill(ctx)
	if err != nil {
		j.Logger.Error("backup-drill: failed", "err", err)
		msg := drillTruncate(err.Error(), 200)
		j.writeResult(ctx, "failed: "+msg)
		j.writeDrillRow(ctx, started, false, 0, msg)
		return
	}
	j.Logger.Info("backup-drill: ok", "rows_replayed", rows)
	j.writeResult(ctx, "ok")
	j.writeDrillRow(ctx, started, true, rows, "")
}

func (j *BackupDrillJob) runDrill(ctx context.Context) (int, error) {
	db := j.DB()
	if db == nil {
		return 0, errors.New("db not ready")
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
		return 0, fmt.Errorf("no succeeded backup found: %w", err)
	}
	encrypted := encInt == 1
	j.Logger.Info("backup-drill: using backup", "job_id", jobID, "artifact", artifactKey)

	// 2. Load destination (GetDestination decrypts config for us).
	svc := &backup.Service{DB: j.DB, State: j.State, Logger: j.Logger}
	dest, err := svc.GetDestination(ctx, destID)
	if err != nil {
		return 0, fmt.Errorf("load destination: %w", err)
	}
	if dest.Kind != backup.KindLocal {
		j.Logger.Warn("backup-drill: skipped — drill only supports 'local' destinations",
			"kind", dest.Kind)
		return 0, fmt.Errorf("drill not implemented for destination kind %q (only 'local' supported)", dest.Kind)
	}

	// 3. Read artifact from local filesystem (cap at 500 MB to avoid OOM).
	root := strings.TrimSpace(dest.Config["path"])
	if root == "" {
		return 0, errors.New("local destination path not configured")
	}
	artifactPath := filepath.Join(root, artifactKey)
	const maxArtifactBytes = 500 << 20
	fi, err := os.Stat(artifactPath)
	if err != nil {
		return 0, fmt.Errorf("stat artifact %s: %w", artifactPath, err)
	}
	if fi.Size() > maxArtifactBytes {
		return 0, fmt.Errorf("artifact %s too large (%d bytes; limit %d)", artifactPath, fi.Size(), maxArtifactBytes)
	}
	raw, err := os.ReadFile(artifactPath)
	if err != nil {
		return 0, fmt.Errorf("read artifact %s: %w", artifactPath, err)
	}

	// 4. Decrypt if needed.
	src := io.Reader(bytes.NewReader(raw))
	if encrypted {
		if j.State == nil {
			return 0, errors.New("encrypted artifact but State not wired")
		}
		key, err := j.State.DeriveBackupKey()
		if err != nil {
			return 0, fmt.Errorf("derive backup key: %w", err)
		}
		var dec bytes.Buffer
		if err := backup.StreamDecrypt(bytes.NewReader(raw), &dec, key); err != nil {
			return 0, fmt.Errorf("decrypt artifact: %w", err)
		}
		src = &dec
	}

	// 5. Extract dump.sql from tar.gz.
	dumpSQL, err := extractDumpSQL(src)
	if err != nil {
		return 0, fmt.Errorf("extract dump.sql: %w", err)
	}

	// 6. Restore into a scratch database. On SQLite that is a throwaway file;
	// on MySQL a side-schema on the production server.
	if store.Driver() == "sqlite3" {
		return j.restoreSQLite(ctx, dumpSQL)
	}
	// Use full timestamp so re-runs on the same day get a fresh empty schema.
	drillSchema := "hpg_drill_" + time.Now().UTC().Format("20060102_150405")
	drillDSN, err := j.drillDSN(drillSchema)
	if err != nil {
		return 0, fmt.Errorf("build drill dsn: %w", err)
	}
	drillDB, err := sql.Open("mysql", drillDSN)
	if err != nil {
		return 0, fmt.Errorf("open drill db: %w", err)
	}
	defer drillDB.Close()
	drillDB.SetMaxOpenConns(1)
	drillDB.SetConnMaxLifetime(5 * time.Minute)

	// 7. Create temp schema — fail gracefully if the DB user lacks CREATE privilege.
	if _, err := drillDB.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS `"+drillSchema+"`"); err != nil {
		return 0, fmt.Errorf("CREATE DATABASE %s: %w (ensure DB user has CREATE privilege)", drillSchema, err)
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
	rowsReplayed := j.replaySQL(restoreCtx, drillDB, dumpSQL)

	// 9. Verify core tables — use restoreCtx so it doesn't time out after replay.
	found, err := j.countCoreTables(restoreCtx, drillDB)
	if err != nil {
		return 0, fmt.Errorf("verify tables: %w", err)
	}
	if found < minTableCount {
		return 0, fmt.Errorf("only %d/%d core tables present after restore", found, minTableCount)
	}
	j.Logger.Info("backup-drill: tables verified", "found", found, "required", minTableCount)
	return rowsReplayed, nil
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
// Returns the count of statements that executed without error.
// restoreSQLite replays the dump into a temp-file SQLite database and verifies
// the core tables arrived. Same contract as the MySQL path; the scratch DB is
// a file because that is the whole engine - no server, no side schema.
func (j *BackupDrillJob) restoreSQLite(ctx context.Context, dumpSQL string) (int, error) {
	dir, err := os.MkdirTemp("", "hpg-drill-*")
	if err != nil {
		return 0, fmt.Errorf("mkdir drill dir: %w", err)
	}
	defer os.RemoveAll(dir)

	drillDB, err := sql.Open("sqlite", filepath.Join(dir, "drill.db"))
	if err != nil {
		return 0, fmt.Errorf("open drill db: %w", err)
	}
	defer drillDB.Close()
	drillDB.SetMaxOpenConns(1)

	restoreCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// SplitSQLStatements (not the ";\n" split): sqlite dump values keep raw
	// newlines and semicolons inside their quotes.
	var rowsReplayed int
	for _, stmt := range backup.SplitSQLStatements(dumpSQL) {
		if isDangerousSQL(stmt) {
			j.Logger.Debug("backup-drill: skipping dangerous stmt", "stmt_prefix", drillTruncate(stmt, 80))
			continue
		}
		if _, err := drillDB.ExecContext(restoreCtx, stmt); err != nil {
			j.Logger.Debug("backup-drill: stmt error (non-fatal)",
				"err", err, "stmt_prefix", drillTruncate(stmt, 80))
		} else {
			rowsReplayed++
		}
	}

	found := 0
	for _, t := range coreTables {
		var n int
		if err := drillDB.QueryRowContext(restoreCtx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?`, t,
		).Scan(&n); err != nil {
			return rowsReplayed, fmt.Errorf("verify tables: %w", err)
		}
		if n > 0 {
			found++
		}
	}
	if found < minTableCount {
		return rowsReplayed, fmt.Errorf("only %d/%d core tables present after restore", found, minTableCount)
	}
	j.Logger.Info("backup-drill: tables verified", "found", found, "required", minTableCount)
	return rowsReplayed, nil
}

func (j *BackupDrillJob) replaySQL(ctx context.Context, db *sql.DB, dump string) int {
	stmts := strings.Split(dump, ";\n")
	var ok int
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
		} else {
			ok++
		}
	}
	return ok
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

// writeDrillRow appends one row to restore_drill_status for history and UI.
// rows parameter is 0 when not meaningful (error path or future extension).
func (j *BackupDrillJob) writeDrillRow(ctx context.Context, started time.Time, success bool, rows int, errMsg string) {
	db := j.DB()
	if db == nil {
		return
	}
	finished := time.Now().UTC()
	var errVal interface{} = nil
	if errMsg != "" {
		errVal = errMsg
	}
	var rowsVal interface{} = nil
	if rows > 0 {
		rowsVal = rows
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO restore_drill_status (started_at, finished_at, success, rows_replayed, error_message)
		 VALUES (?, ?, ?, ?, ?)`,
		started.Format("2006-01-02 15:04:05"),
		finished.Format("2006-01-02 15:04:05"),
		success, rowsVal, errVal,
	); err != nil {
		j.Logger.Warn("backup-drill: persist row failed", "err", err)
	}
}

// writeResult upserts drill outcome into the settings table.
func (j *BackupDrillJob) writeResult(ctx context.Context, status string) {
	db := j.DB()
	if db == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	upsert := func(key, val string) {
		if _, err := db.ExecContext(ctx, store.UpsertSettingSQL(), key, val, 0); err != nil {
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
