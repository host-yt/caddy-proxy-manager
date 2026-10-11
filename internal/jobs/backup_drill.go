// Package jobs contains standalone background jobs that don't belong in a
// domain package.
package jobs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"
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
	var jobID, destID, wantSize int64
	var artifactKey, wantSHA string
	var encInt int
	err := db.QueryRowContext(ctx,
		`SELECT id, destination_id, artifact_key, COALESCE(sha256, ''), size_bytes, encrypted
		 FROM backup_jobs
		 WHERE status = 'succeeded' AND kind <> 'verification' AND artifact_key <> ''
		 ORDER BY id DESC LIMIT 1`,
	).Scan(&jobID, &destID, &artifactKey, &wantSHA, &wantSize, &encInt)
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
	// The file is replayed as SQL, so it must be byte-identical to what the backup job recorded.
	if err := checkArtifact(raw, wantSize, wantSHA); err != nil {
		return 0, err
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
	var drillDB *sql.DB
	if extDSN := os.Getenv("HPG_DRILL_DSN"); extDSN != "" {
		// Hosting plans without CREATE DATABASE: replay into a dedicated empty DB.
		db, err := j.openExternalDrillDB(ctx, extDSN)
		if err != nil {
			return 0, err
		}
		drillDB = db
		defer db.Close()
		defer func() {
			dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := dropAllTables(dropCtx, db); err != nil {
				j.Logger.Warn("backup-drill: cleanup failed", "err", err)
			}
		}()
	} else {
		// Use full timestamp so re-runs on the same day get a fresh empty schema.
		drillSchema := "hpg_drill_" + time.Now().UTC().Format("20060102_150405")
		// Bootstrap connection with NO default schema: putting the not-yet-created
		// drill schema in the DSN makes the first query fail with Error 1049.
		bootDSN, err := j.drillDSN("")
		if err != nil {
			return 0, fmt.Errorf("build drill dsn: %w", err)
		}
		bootDB, err := sql.Open("mysql", bootDSN)
		if err != nil {
			return 0, fmt.Errorf("open drill bootstrap db: %w", err)
		}
		defer bootDB.Close()
		bootDB.SetMaxOpenConns(1)
		bootDB.SetConnMaxLifetime(5 * time.Minute)

		// 7. Create temp schema - fail gracefully if the DB user lacks CREATE privilege.
		if _, err := bootDB.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS `"+drillSchema+"`"); err != nil {
			return 0, createDBError(drillSchema, err)
		}
		j.Logger.Debug("backup-drill: schema created", "schema", drillSchema)

		defer func() {
			dropCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := bootDB.ExecContext(dropCtx, "DROP DATABASE IF EXISTS `"+drillSchema+"`"); err != nil {
				j.Logger.Warn("backup-drill: DROP schema failed", "schema", drillSchema, "err", err)
			} else {
				j.Logger.Debug("backup-drill: schema dropped", "schema", drillSchema)
			}
		}()

		drillDSN, err := j.drillDSN(drillSchema)
		if err != nil {
			return 0, fmt.Errorf("build drill dsn: %w", err)
		}
		drillDB, err = sql.Open("mysql", drillDSN)
		if err != nil {
			return 0, fmt.Errorf("open drill db: %w", err)
		}
		defer drillDB.Close()
		drillDB.SetMaxOpenConns(1)
		drillDB.SetConnMaxLifetime(5 * time.Minute)
	}

	// 8. Replay dump.
	restoreCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	rowsReplayed, err := j.replaySQL(restoreCtx, drillDB, strings.Split(dumpSQL, ";\n"))
	if err != nil {
		return 0, err
	}

	// 9. Verify core tables — use restoreCtx so it doesn't time out after replay.
	found, err := j.countCoreTables(restoreCtx, drillDB)
	if err != nil {
		return 0, fmt.Errorf("verify tables: %w", err)
	}
	if found < minTableCount {
		return 0, fmt.Errorf("only %d/%d core tables present after restore", found, minTableCount)
	}
	if err := checkCoreRows(restoreCtx, drillDB); err != nil {
		return rowsReplayed, err
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
	rowsReplayed, err := j.replaySQL(restoreCtx, drillDB, backup.SplitSQLStatements(dumpSQL))
	if err != nil {
		return 0, err
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
	if err := checkCoreRows(restoreCtx, drillDB); err != nil {
		return rowsReplayed, err
	}
	j.Logger.Info("backup-drill: tables verified", "found", found, "required", minTableCount)
	return rowsReplayed, nil
}

// replaySQL executes dump statements into the drill DB. Any statement outside
// the shapes our own dumpers emit, or any failing statement, fails the drill:
// a dump that only half restores is not a usable backup.
// Returns the count of statements executed.
func (j *BackupDrillJob) replaySQL(ctx context.Context, db *sql.DB, stmts []string) (int, error) {
	var ok int
	for _, stmt := range stmts {
		stmt = stripLeadingComments(stmt)
		if stmt == "" {
			continue
		}
		if !allowedDrillSQL(stmt) {
			return ok, fmt.Errorf("dump contains a statement the drill does not replay: %q", drillTruncate(stmt, 60))
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return ok, fmt.Errorf("replay statement %d (%q): %w", ok+1, drillTruncate(stmt, 60), err)
		}
		ok++
	}
	return ok, nil
}

// checkArtifact pins the artifact to the size and SHA-256 recorded by its backup job.
func checkArtifact(raw []byte, wantSize int64, wantSHA string) error {
	if wantSHA == "" {
		return errors.New("backup job has no recorded sha256; refusing to replay artifact")
	}
	if int64(len(raw)) != wantSize {
		return fmt.Errorf("artifact size mismatch: recorded %d, got %d", wantSize, len(raw))
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, wantSHA) {
		return fmt.Errorf("artifact sha256 mismatch: recorded %s, got %s", wantSHA, got)
	}
	return nil
}

// stripLeadingComments drops blank and "--" lines in front of a statement.
func stripLeadingComments(stmt string) string {
	stmt = strings.TrimSpace(stmt)
	for strings.HasPrefix(stmt, "--") {
		nl := strings.IndexByte(stmt, '\n')
		if nl < 0 {
			return ""
		}
		stmt = strings.TrimSpace(stmt[nl+1:])
	}
	return stmt
}

// drillAllowed lists the only statement shapes the MySQL and SQLite dumpers
// emit; a strict allowlist, so comments, qualified names or extra clauses can't slip by.
var drillAllowed = []*regexp.Regexp{
	regexp.MustCompile(`^SET (NAMES utf8mb4|FOREIGN_KEY_CHECKS = [01]|UNIQUE_CHECKS = [01]|SQL_MODE = '[A-Z_,]*')$`),
	regexp.MustCompile(`^PRAGMA foreign_keys=(ON|OFF)$`),
	regexp.MustCompile("^DROP TABLE IF EXISTS `\\w+`$"),
	regexp.MustCompile("^CREATE TABLE (IF NOT EXISTS )?[`\"]?\\w+[`\"]?\\s*\\("),
	regexp.MustCompile("^CREATE (UNIQUE )?INDEX (IF NOT EXISTS )?[`\"]?\\w+[`\"]? ON [`\"]?\\w+[`\"]?\\s*\\("),
	regexp.MustCompile("^INSERT INTO `\\w+` \\(`\\w+`(, `\\w+`)*\\) VALUES\\s?\\("),
}

// drillDeniedDDL catches CREATE TABLE options that reach outside the scratch schema.
var drillDeniedDDL = regexp.MustCompile(`(?i)\b(DATA|INDEX)\s+DIRECTORY\b|\bCONNECTION\s*=|\bENGINE\s*=\s*(FEDERATED|CONNECT)\b|\bSELECT\b`)

func allowedDrillSQL(stmt string) bool {
	if strings.HasPrefix(stmt, "CREATE ") && drillDeniedDDL.MatchString(stmt) {
		return false
	}
	for _, re := range drillAllowed {
		if re.MatchString(stmt) {
			return true
		}
	}
	return false
}

// populatedTables must hold rows in any backup of an installed panel.
var populatedTables = []string{"settings", "users"}

// checkCoreRows fails when a table every installed panel populates came back empty.
func checkCoreRows(ctx context.Context, db *sql.DB) error {
	for _, t := range populatedTables {
		var n int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+t+"`").Scan(&n); err != nil {
			return fmt.Errorf("count %s: %w", t, err)
		}
		if n == 0 {
			return fmt.Errorf("table %s is empty after restore", t)
		}
	}
	return nil
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

// createDBError maps MySQL access-denied (1044/1227) to an actionable hint.
func createDBError(schema string, err error) error {
	var me *mysqldrv.MySQLError
	if errors.As(err, &me) && (me.Number == 1044 || me.Number == 1227) {
		return fmt.Errorf("DB user cannot create databases; create an empty database and set HPG_DRILL_DSN: %w", err)
	}
	return fmt.Errorf("CREATE DATABASE %s: %w", schema, err)
}

// openExternalDrillDB opens HPG_DRILL_DSN, refuses the production schema and
// wipes the target's tables so the replay starts clean.
func (j *BackupDrillJob) openExternalDrillDB(ctx context.Context, dsn string) (*sql.DB, error) {
	cfg, err := mysqldrv.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse HPG_DRILL_DSN: %w", err)
	}
	cfg.ParseTime, cfg.Loc, cfg.Params = true, time.UTC, map[string]string{"charset": "utf8mb4"}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("open HPG_DRILL_DSN: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)
	var target string
	if err := db.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&target); err != nil || target == "" {
		db.Close()
		return nil, fmt.Errorf("HPG_DRILL_DSN must name a database (err=%v)", err)
	}
	prod, err := j.prodSchema(ctx)
	if err == nil && target == prod {
		err = errors.New("HPG_DRILL_DSN points at the production database")
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	if err := dropAllTables(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("clean drill db: %w", err)
	}
	return db, nil
}

func (j *BackupDrillJob) prodSchema(ctx context.Context) (string, error) {
	pdb := j.DB()
	if pdb == nil {
		return "", errors.New("production db not available")
	}
	var name string
	if err := pdb.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&name); err != nil {
		return "", fmt.Errorf("resolve production schema: %w", err)
	}
	return name, nil
}

// dropAllTables empties the current schema (FK checks off on one connection).
func dropAllTables(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()")
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0"); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), "SET FOREIGN_KEY_CHECKS=1")
	for _, n := range names {
		if _, err := conn.ExecContext(ctx, "DROP TABLE IF EXISTS `"+strings.ReplaceAll(n, "`", "``")+"`"); err != nil {
			return err
		}
	}
	return nil
}
