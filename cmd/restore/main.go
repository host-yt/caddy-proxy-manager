// hpg-restore is a small standalone tool to decrypt + unpack a backup
// artifact produced by the panel's backup module.
//
//	hpg-restore --in artifact.tgz.age --secret <APP_SECRET> --out ./restored
//
// It does NOT touch your live DB or filesystem. It only decrypts the file
// (or skips decryption if --in is already a plain .tgz), expands the tar
// into the output directory, and prints a manifest. Replay is a manual
// step:
//
//	mysql -h ... -u ... -p hostyt_proxy < ./restored/dump.sql
//	cp ./restored/install_state.json /panel/data/install_state.json
//	cp ./restored/wg/*               /panel/wg/
//
// The deliberate split keeps the tool harmless: nothing to undo, nothing to
// damage. Restoring is rare and humans should eyeball the artifact first.
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/hkdf"

	"github.com/host-yt/caddy-proxy-manager/internal/backup"
)

func main() {
	in := flag.String("in", "", "encrypted/plain backup artifact (.tgz.age or .tgz)")
	secret := flag.String("secret", os.Getenv("APP_SECRET"), "APP_SECRET (or env APP_SECRET). Required for .age files.")
	out := flag.String("out", "./restored", "output directory (must not exist or be empty)")
	flag.Parse()

	if *in == "" {
		fail("missing --in")
	}
	if err := run(*in, *secret, *out); err != nil {
		fail(err.Error())
	}
}

func run(in, secret, out string) error {
	if err := ensureEmptyDir(out); err != nil {
		return err
	}
	f, err := os.Open(in)
	if err != nil {
		return fmt.Errorf("open in: %w", err)
	}
	defer f.Close()

	var src io.Reader = f
	if strings.HasSuffix(in, ".age") || strings.HasSuffix(in, ".enc") {
		if secret == "" {
			return errors.New("encrypted artifact but no --secret / APP_SECRET")
		}
		key := deriveKey(secret)
		pr, pw := io.Pipe()
		go func() {
			defer pw.Close()
			if err := backup.StreamDecrypt(f, pw, key); err != nil {
				_ = pw.CloseWithError(err)
			}
		}()
		src = pr
	}

	gz, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	fmt.Printf("Restoring %s → %s\n", in, out)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		// Defence in depth: refuse traversal.
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || strings.HasPrefix(clean, "/") {
			return fmt.Errorf("unsafe path in archive: %q", hdr.Name)
		}
		target := filepath.Join(out, clean)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		of, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		n, err := io.Copy(of, tr)
		_ = of.Close()
		if err != nil {
			return err
		}
		fmt.Printf("  %s (%d bytes)\n", clean, n)
	}
	fmt.Println("Done. Restore is manual:")
	fmt.Println("  mysql ... < " + filepath.Join(out, "dump.sql"))
	fmt.Println("  cp " + filepath.Join(out, "install_state.json") + " <panel-data>/install_state.json")
	fmt.Println("  cp " + filepath.Join(out, "wg/*") + " <panel>/wg/")
	return nil
}

// deriveKey reproduces installstate.Manager.DeriveBackupKey exactly:
// HKDF(APP_SECRET, info="hpg/install-state/v1") → 32 bytes, then
// HKDF(that, info="hpg/backup/v1") → 32 bytes. The chain must match the
// panel's at-rest crypto byte-for-byte or every backup is undecryptable.
func deriveKey(secret string) []byte {
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte("hpg/install-state/v1"))
	stateKey := make([]byte, 32)
	_, _ = io.ReadFull(r, stateKey)
	r2 := hkdf.New(sha256.New, stateKey, nil, []byte("hpg/backup/v1"))
	backupKey := make([]byte, 32)
	_, _ = io.ReadFull(r2, backupKey)
	return backupKey
}

func ensureEmptyDir(p string) error {
	if err := os.MkdirAll(p, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("output dir %q is not empty", p)
	}
	return nil
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}
