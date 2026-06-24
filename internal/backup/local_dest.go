package backup

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Local filesystem destination.
//
// Config keys:
//
//	path       absolute directory to write artifacts into (required)
type localDest struct {
	root string
}

func newLocalDest(cfg map[string]string) (*localDest, error) {
	root := strings.TrimSpace(cfg["path"])
	if root == "" {
		return nil, errors.New("local: path required")
	}
	if !filepath.IsAbs(root) {
		return nil, errors.New("local: path must be absolute")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &localDest{root: root}, nil
}

func (d *localDest) Upload(ctx context.Context, key string, body io.Reader, _ int64) error {
	if strings.Contains(key, "..") {
		return errors.New("local: key contains traversal")
	}
	full := filepath.Join(d.root, key)
	tmp := full + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, full)
}

func (d *localDest) Download(_ context.Context, key string) (io.ReadCloser, error) {
	if strings.Contains(key, "..") {
		return nil, errors.New("local: key contains traversal")
	}
	return os.Open(filepath.Join(d.root, key))
}

func (d *localDest) Delete(_ context.Context, key string) error {
	if strings.Contains(key, "..") {
		return errors.New("local: key contains traversal")
	}
	err := os.Remove(filepath.Join(d.root, key))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
