package geoip

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxMind permalink for the GeoLite2-Country DB. Auth is HTTP Basic with
// username=account_id, password=license_key.
const MaxMindDownloadURL = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"

// maxMmdbBytes caps the extracted mmdb to guard against a malicious/huge
// archive decompressing into memory. GeoLite2-Country is ~6 MB; 128 MB is safe.
const maxMmdbBytes = 128 << 20

// downloadClient has a generous timeout because the tar.gz is several MB.
var downloadClient = &http.Client{Timeout: 120 * time.Second}

// DownloadCountryMMDB fetches the GeoLite2-Country tar.gz from MaxMind, extracts
// the .mmdb, and returns its bytes. Network errors and a missing/duplicate mmdb
// surface as errors so the caller can skip rewriting on failure.
func DownloadCountryMMDB(ctx context.Context, accountID, licenseKey string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, MaxMindDownloadURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(accountID, licenseKey)
	resp, err := downloadClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maxmind download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 401 = bad creds; surface status only, never the body (may echo creds).
		return nil, fmt.Errorf("maxmind download: status %d", resp.StatusCode)
	}
	return ExtractMMDBFromTarGz(resp.Body)
}

// MaxMindASNDownloadURL is the MaxMind permalink for GeoLite2-ASN.
const MaxMindASNDownloadURL = "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz"

// DownloadASNMMDB fetches the GeoLite2-ASN tar.gz from MaxMind and returns the mmdb bytes.
func DownloadASNMMDB(ctx context.Context, accountID, licenseKey string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, MaxMindASNDownloadURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(accountID, licenseKey)
	resp, err := downloadClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("maxmind ASN download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("maxmind ASN download: status %d", resp.StatusCode)
	}
	return ExtractMMDBFromTarGz(resp.Body)
}

// ExtractMMDBFromTarGz gunzips+untars the stream and returns the single .mmdb
// entry. Errors if there are zero or more than one .mmdb files (ambiguous).
func ExtractMMDBFromTarGz(src io.Reader) ([]byte, error) {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var found []byte
	count := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}
		count++
		data, err := io.ReadAll(io.LimitReader(tr, maxMmdbBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read mmdb: %w", err)
		}
		if int64(len(data)) > maxMmdbBytes {
			return nil, fmt.Errorf("mmdb exceeds %d byte limit", maxMmdbBytes)
		}
		found = data
	}
	if count == 0 {
		return nil, errors.New("no .mmdb file in archive")
	}
	if count > 1 {
		return nil, fmt.Errorf("expected exactly one .mmdb, found %d", count)
	}
	if len(found) == 0 {
		return nil, errors.New("extracted mmdb is empty")
	}
	// Light sanity check: the MaxMind metadata marker must appear near the end.
	if !hasMaxMindMarker(found) {
		return nil, errors.New("extracted file is not a MaxMind mmdb")
	}
	return found, nil
}

// maxMindMarker delimits the metadata section of every MaxMind DB file.
var maxMindMarker = []byte("\xab\xcd\xefMaxMind.com")

// hasMaxMindMarker reports whether the metadata marker appears in the tail of
// the file (the marker precedes the metadata, which lives at the very end).
func hasMaxMindMarker(b []byte) bool {
	const window = 1 << 20 // marker is well within the last MB
	start := 0
	if len(b) > window {
		start = len(b) - window
	}
	return strings.Contains(string(b[start:]), string(maxMindMarker))
}

// SHA256Hex returns the lowercase hex sha256 of b.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FileSHA256Hex returns the hex sha256 of a file, or "" if it doesn't exist.
func FileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteAtomic writes data to path via a same-dir temp file + fsync + rename so
// readers never observe a partial mmdb. Creates the parent dir (0755) if absent.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
