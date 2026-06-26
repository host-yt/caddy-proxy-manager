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
	if err := j.refresh(ctx); err != nil {
		j.Logger.Warn("geoip: refresh failed", "err", err)
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

func shaPrefix(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
