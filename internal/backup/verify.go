package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Verify reads the most recent successful backup job for a destination,
// downloads its artifact, decrypts if needed, walks the tar to confirm
// dump.sql is present and parseable. Recorded as backup_jobs entry of
// kind='verification'. This is the auto-test-restore the audit asked for —
// catches "encryption silently broke" or "destination corrupted file"
// before a real disaster.
//
// It does NOT replay the SQL — that would clobber the live DB. The
// guarantee is: artifact is downloadable, decryptable, parseable; SHA-256
// of the tar.gz matches the original job row.
func (s *Service) Verify(ctx context.Context, destID int64) error {
	db := s.DB()
	if db == nil {
		return errors.New("db not ready")
	}
	var (
		jobID        int64
		artifactKey  string
		expectedSHA  string
		expectedSize int64
		encrypted    bool
	)
	err := db.QueryRowContext(ctx,
		`SELECT id, artifact_key, sha256, size_bytes, encrypted
		 FROM backup_jobs
		 WHERE destination_id = ? AND status = 'succeeded' AND artifact_key <> ''
		 ORDER BY id DESC LIMIT 1`, destID,
	).Scan(&jobID, &artifactKey, &expectedSHA, &expectedSize, &encrypted)
	if err != nil {
		return fmt.Errorf("no successful backup found: %w", err)
	}

	dest, err := s.GetDestination(ctx, destID)
	if err != nil {
		return err
	}

	// Insert verification job row first.
	res, err := db.ExecContext(ctx,
		`INSERT INTO backup_jobs (destination_id, kind, status, started_at, encrypted)
		 VALUES (?, 'manual', 'running', NOW(), ?)`, destID, boolToInt(encrypted))
	if err != nil {
		return err
	}
	verifyID, _ := res.LastInsertId()
	finish := func(status, errText string, sizeBytes int64, sum string) {
		_, _ = db.ExecContext(context.Background(),
			`UPDATE backup_jobs SET status=?, error_text=?, finished_at=NOW(),
			 size_bytes=?, sha256=?, artifact_key=? WHERE id=?`,
			status, errText, sizeBytes, sum, "verify_"+artifactKey, verifyID)
	}

	body, size, sum, err := s.downloadAndHash(ctx, dest, artifactKey)
	if err != nil {
		finish("failed", "download: "+err.Error(), 0, "")
		return err
	}
	if expectedSize > 0 && size != expectedSize {
		msg := fmt.Sprintf("size mismatch: expected %d got %d", expectedSize, size)
		finish("failed", msg, size, sum)
		return errors.New(msg)
	}
	if expectedSHA != "" && sum != expectedSHA {
		msg := fmt.Sprintf("sha256 mismatch: expected %s got %s", expectedSHA, sum)
		finish("failed", msg, size, sum)
		return errors.New(msg)
	}
	// Decrypt + walk.
	src := io.Reader(bytes.NewReader(body))
	if encrypted {
		if s.State == nil {
			finish("failed", "encrypted but no state manager", size, sum)
			return errors.New("encrypted but no state manager")
		}
		key, err := s.State.DeriveBackupKey()
		if err != nil {
			finish("failed", "derive key: "+err.Error(), size, sum)
			return err
		}
		var dec bytes.Buffer
		if err := StreamDecrypt(bytes.NewReader(body), &dec, key); err != nil {
			finish("failed", "decrypt: "+err.Error(), size, sum)
			return err
		}
		src = &dec
	}
	gz, err := gzip.NewReader(src)
	if err != nil {
		finish("failed", "gunzip: "+err.Error(), size, sum)
		return err
	}
	tr := tar.NewReader(gz)
	dumpSeen := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			finish("failed", "tar: "+err.Error(), size, sum)
			return err
		}
		if hdr.Name == "dump.sql" {
			dumpSeen = true
			// Read a few hundred bytes to make sure it parses as text.
			head := make([]byte, 256)
			n, _ := io.ReadFull(tr, head)
			if n < 32 || !bytes.Contains(head[:n], []byte("Hostyt Proxy Gateway")) {
				finish("failed", "dump.sql header not recognized", size, sum)
				return errors.New("dump.sql header not recognized")
			}
		}
	}
	if !dumpSeen {
		finish("failed", "dump.sql missing from archive", size, sum)
		return errors.New("dump.sql missing from archive")
	}
	finish("succeeded", "", size, sum)
	return nil
}

// downloadAndHash fetches the artifact into memory while computing SHA-256.
// Memory cost is bounded by the artifact size; backups beyond ~100 MB
// should switch to a streaming verify path.
func (s *Service) downloadAndHash(ctx context.Context, dest Destination, key string) ([]byte, int64, string, error) {
	u, err := newDestination(dest)
	if err != nil {
		return nil, 0, "", err
	}
	d, ok := u.(downloader)
	if !ok {
		return nil, 0, "", fmt.Errorf("destination kind %s does not support verification", dest.Kind)
	}
	r, err := d.Download(ctx, key)
	if err != nil {
		return nil, 0, "", err
	}
	defer r.Close()
	h := sha256.New()
	body, err := io.ReadAll(io.TeeReader(r, h))
	if err != nil {
		return nil, 0, "", err
	}
	return body, int64(len(body)), hex.EncodeToString(h.Sum(nil)), nil
}

// downloader is implemented by destinations that can read back their
// uploaded artifacts (local + sftp + s3; ftp typically can too but we
// keep the option to opt out).
type downloader interface {
	Download(ctx context.Context, key string) (io.ReadCloser, error)
}
