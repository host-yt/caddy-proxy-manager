package jobs

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
)

const geoipDefaultInterval = 24 * time.Hour

// GeoIPUpdateJob downloads the MaxMind GeoLite2-Country DB centrally (leader-only)
// and writes it to geoip.DBPath. The panel is itself a Caddy node, so it needs
// the file locally; node-agents pull it from the panel afterwards.
type GeoIPUpdateJob struct {
	// DB returns the live pool (func because the pool may not be ready at wiring time).
	DB func() *sql.DB
	// State decrypts the stored MaxMind credentials.
	State *installstate.Manager
	// Logger for structured output; credentials are never logged.
	Logger *slog.Logger
	// Interval between runs; 0 uses the 24 h default.
	Interval time.Duration
}

func (j *GeoIPUpdateJob) interval() time.Duration {
	if j.Interval > 0 {
		return j.Interval
	}
	return geoipDefaultInterval
}

// Run blocks until ctx is cancelled, refreshing the DB on each interval tick.
func (j *GeoIPUpdateJob) Run(ctx context.Context) {
	// Refresh once at startup so a freshly-configured panel doesn't wait a day.
	j.RunOnce(ctx)
	t := time.NewTimer(j.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		j.RunOnce(ctx)
		t.Reset(j.interval())
	}
}

// RunOnce performs a single refresh; also used by the manual UI trigger.
func (j *GeoIPUpdateJob) RunOnce(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			j.Logger.Error("geoip: panic", "panic", r)
		}
	}()
	err := j.refresh(ctx)
	if err != nil {
		j.Logger.Warn("geoip: refresh failed", "err", err)
	}
	// Persist the outcome so the UI can show why a refresh failed (or clear it
	// on success) instead of a silent "no database".
	if db := j.DB(); db != nil {
		j.recordOutcome(ctx, db, err)
	}
}

func (j *GeoIPUpdateJob) refresh(ctx context.Context) error {
	db := j.DB()
	if db == nil {
		return errors.New("db not ready")
	}
	accountID, licenseKey, err := j.loadCreds(ctx, db)
	if err != nil {
		return err
	}
	if accountID == "" || licenseKey == "" {
		// Absent creds is a normal state, not an error: no-op cleanly.
		j.Logger.Info("geoip: not configured, skipping")
		return nil
	}

	dlCtx, cancel := context.WithTimeout(ctx, 130*time.Second)
	defer cancel()
	data, err := geoip.DownloadCountryMMDB(dlCtx, accountID, licenseKey)
	if err != nil {
		return err
	}
	newSHA := geoip.SHA256Hex(data)

	// Skip the rewrite when the on-disk file already matches - avoids needless
	// fsync churn and a fetched_at bump on unchanged DBs.
	curSHA, _ := geoip.FileSHA256Hex(geoip.DBPath)
	if curSHA == newSHA && curSHA != "" {
		j.Logger.Info("geoip: unchanged", "sha256_prefix", shaPrefix(newSHA))
		j.writeMeta(ctx, db, newSHA, len(data))
		return nil
	}
	if err := geoip.WriteAtomic(geoip.DBPath, data); err != nil {
		return err
	}
	j.writeMeta(ctx, db, newSHA, len(data))
	j.Logger.Info("geoip: updated", "size", len(data), "sha256_prefix", shaPrefix(newSHA))
	return nil
}

// loadCreds reads + decrypts the MaxMind account id and license key.
func (j *GeoIPUpdateJob) loadCreds(ctx context.Context, db *sql.DB) (accountID, licenseKey string, err error) {
	if j.State == nil {
		return "", "", errors.New("installstate not wired")
	}
	rows, err := db.QueryContext(ctx,
		"SELECT `key`, value, is_encrypted FROM settings WHERE `key` IN ('geoip.account_id','geoip.license_key')")
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		var enc bool
		if err := rows.Scan(&k, &v, &enc); err != nil {
			continue
		}
		if enc {
			if dec, derr := j.State.Decrypt(v); derr == nil {
				v = dec
			} else {
				v = ""
			}
		}
		switch k {
		case "geoip.account_id":
			accountID = v
		case "geoip.license_key":
			licenseKey = v
		}
	}
	return accountID, licenseKey, nil
}

// writeMeta upserts the single geoip_db_meta row.
func (j *GeoIPUpdateJob) writeMeta(ctx context.Context, db *sql.DB, sha string, size int) {
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	if _, err := db.ExecContext(ctx,
		`INSERT INTO geoip_db_meta (id, sha256, size_bytes, fetched_at, source)
		 VALUES (1, ?, ?, ?, 'maxmind')
		 ON DUPLICATE KEY UPDATE sha256=VALUES(sha256), size_bytes=VALUES(size_bytes), fetched_at=VALUES(fetched_at)`,
		sha, size, now); err != nil {
		j.Logger.Warn("geoip: persist meta failed", "err", err)
	}
}

// recordOutcome stamps the last attempt time and either the error text (on
// failure) or clears it (on success). Truncates to the column width.
func (j *GeoIPUpdateJob) recordOutcome(ctx context.Context, db *sql.DB, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	if _, e := db.ExecContext(ctx,
		`INSERT INTO geoip_db_meta (id, last_error, last_attempt_at)
		 VALUES (1, ?, ?)
		 ON DUPLICATE KEY UPDATE last_error=VALUES(last_error), last_attempt_at=VALUES(last_attempt_at)`,
		msg, now); e != nil {
		j.Logger.Warn("geoip: persist outcome failed", "err", e)
	}
}

func shaPrefix(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// GeoIPASNUpdateJob downloads GeoLite2-ASN.mmdb, sharing creds with GeoIPUpdateJob.
type GeoIPASNUpdateJob struct {
	DB       func() *sql.DB
	State    *installstate.Manager
	Logger   *slog.Logger
	Interval time.Duration
}

func (j *GeoIPASNUpdateJob) interval() time.Duration {
	if j.Interval > 0 {
		return j.Interval
	}
	return geoipDefaultInterval
}

// Run blocks until ctx is cancelled, refreshing on each interval tick.
func (j *GeoIPASNUpdateJob) Run(ctx context.Context) {
	j.RunOnce(ctx)
	t := time.NewTimer(j.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		j.RunOnce(ctx)
		t.Reset(j.interval())
	}
}

// RunOnce performs a single ASN DB refresh.
func (j *GeoIPASNUpdateJob) RunOnce(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			j.Logger.Error("geoip-asn: panic", "panic", r)
		}
	}()
	if err := j.refresh(ctx); err != nil {
		j.Logger.Warn("geoip-asn: refresh failed", "err", err)
	}
}

func (j *GeoIPASNUpdateJob) refresh(ctx context.Context) error {
	db := j.DB()
	if db == nil {
		return errors.New("db not ready")
	}
	// Reuse same credentials as GeoIPUpdateJob - MaxMind account is shared.
	rows, err := db.QueryContext(ctx,
		"SELECT `key`, value, is_encrypted FROM settings WHERE `key` IN ('geoip.account_id','geoip.license_key')")
	if err != nil {
		return err
	}
	defer rows.Close()
	var accountID, licenseKey string
	for rows.Next() {
		var k, v string
		var enc bool
		if err2 := rows.Scan(&k, &v, &enc); err2 != nil {
			continue
		}
		if enc {
			if dec, derr := j.State.Decrypt(v); derr == nil {
				v = dec
			} else {
				v = ""
			}
		}
		switch k {
		case "geoip.account_id":
			accountID = v
		case "geoip.license_key":
			licenseKey = v
		}
	}
	if accountID == "" || licenseKey == "" {
		j.Logger.Info("geoip-asn: not configured, skipping")
		return nil
	}
	dlCtx, cancel := context.WithTimeout(ctx, 130*time.Second)
	defer cancel()
	data, err := geoip.DownloadASNMMDB(dlCtx, accountID, licenseKey)
	if err != nil {
		return err
	}
	newSHA := geoip.SHA256Hex(data)
	curSHA, _ := geoip.FileSHA256Hex(geoip.ASNDBPath)
	if curSHA == newSHA && curSHA != "" {
		j.Logger.Info("geoip-asn: unchanged", "sha256_prefix", shaPrefix(newSHA))
		return nil
	}
	if err := geoip.WriteAtomic(geoip.ASNDBPath, data); err != nil {
		return err
	}
	j.Logger.Info("geoip-asn: updated", "size", len(data), "sha256_prefix", shaPrefix(newSHA))
	return nil
}
