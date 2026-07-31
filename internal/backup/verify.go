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
	"os"
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

	artPath, size, sum, err := s.downloadAndHash(ctx, dest, artifactKey, expectedSize)
	if err != nil {
		finish("failed", "download: "+err.Error(), 0, "")
		return err
	}
	defer os.Remove(artPath)
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
	f, err := os.Open(artPath)
	if err != nil {
		finish("failed", "open artifact: "+err.Error(), size, sum)
		return err
	}
	defer f.Close()

	// Decrypt + walk. Both stages read/write through disk, never buffering
	// the whole artifact in memory (BACKUP-VERIFY-01).
	src := io.Reader(f)
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
		decTmp, err := os.CreateTemp("", "hpg-verify-dec-*.bin")
		if err != nil {
			finish("failed", "temp: "+err.Error(), size, sum)
			return err
		}
		decPath := decTmp.Name()
		defer func() {
			decTmp.Close()
			os.Remove(decPath)
		}()
		if err := StreamDecrypt(f, decTmp, key); err != nil {
			finish("failed", "decrypt: "+err.Error(), size, sum)
			return err
		}
		if _, err := decTmp.Seek(0, io.SeekStart); err != nil {
			finish("failed", "seek decrypted: "+err.Error(), size, sum)
			return err
		}
		src = decTmp
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

// maxVerifyBytes is the fallback ceiling used when the recorded artifact
// size is unknown. A malicious/misconfigured destination could otherwise
// serve an unbounded object and OOM the panel.
const maxVerifyBytes = 2 << 30 // 2 GiB

// downloadAndHash streams the artifact into a bounded temp file while
// hashing, never holding it in memory. expectedSize (from backup_jobs), when
// known, is used as the read cap so an oversized/misbehaving destination is
// cut off right at the recorded size rather than after buffering up to
// maxVerifyBytes. Caller owns the returned path and must remove it.
func (s *Service) downloadAndHash(ctx context.Context, dest Destination, key string, expectedSize int64) (string, int64, string, error) {
	u, err := newDestination(dest)
	if err != nil {
		return "", 0, "", err
	}
	d, ok := u.(downloader)
	if !ok {
		return "", 0, "", fmt.Errorf("destination kind %s does not support verification", dest.Kind)
	}
	r, err := d.Download(ctx, key)
	if err != nil {
		return "", 0, "", err
	}
	defer r.Close()
	return streamToTempFile(r, expectedSize)
}

// streamToTempFile copies r into a bounded temp file while hashing, capped
// at expectedSize (when known and smaller) or maxVerifyBytes otherwise.
// io.LimitReader stops pulling from r as soon as the cap is crossed, so a
// reader that never EOFs (a hostile/broken destination) can't be drained
// into memory or disk beyond the cap. Split out from downloadAndHash so the
// bounding behavior is directly testable without a fake Destination.
func streamToTempFile(r io.Reader, expectedSize int64) (string, int64, string, error) {
	limit := int64(maxVerifyBytes)
	if expectedSize > 0 && expectedSize < limit {
		limit = expectedSize
	}

	tmp, err := os.CreateTemp("", "hpg-verify-*.bin")
	if err != nil {
		return "", 0, "", err
	}
	tmpPath := tmp.Name()
	fail := func(err error) (string, int64, string, error) {
		tmp.Close()
		os.Remove(tmpPath)
		return "", 0, "", err
	}

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, limit+1))
	if err != nil {
		return fail(err)
	}
	if n > limit {
		return fail(fmt.Errorf("artifact exceeds verify size limit of %d bytes", limit))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", 0, "", err
	}
	return tmpPath, n, hex.EncodeToString(h.Sum(nil)), nil
}

// downloader is implemented by destinations that can read back their
// uploaded artifacts (local + sftp + s3; ftp typically can too but we
// keep the option to opt out).
type downloader interface {
	Download(ctx context.Context, key string) (io.ReadCloser, error)
}
