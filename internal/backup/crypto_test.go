package backup

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestStreamEncryptDecryptRoundtrip(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"small", 32},
		{"under-chunk", chunkSize - 1},
		{"exact-chunk", chunkSize},
		{"multi-chunk", chunkSize*3 + 17},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			plain := make([]byte, c.size)
			if _, err := rand.Read(plain); err != nil {
				t.Fatal(err)
			}
			var enc bytes.Buffer
			w, err := newStreamEncryptWriter(&enc, key)
			if err != nil {
				t.Fatalf("encrypt writer: %v", err)
			}
			if _, err := io.Copy(w, bytes.NewReader(plain)); err != nil {
				t.Fatalf("encrypt copy: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			var dec bytes.Buffer
			if err := StreamDecrypt(&enc, &dec, key); err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(plain, dec.Bytes()) {
				t.Fatalf("roundtrip mismatch: in %d bytes, out %d", len(plain), dec.Len())
			}
		})
	}
}

func TestStreamDecryptWrongKey(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x01}, 32)
	k2 := bytes.Repeat([]byte{0x02}, 32)
	plain := []byte("hello world")
	var enc bytes.Buffer
	w, err := newStreamEncryptWriter(&enc, k1)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(plain)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if err := StreamDecrypt(&enc, &dec, k2); err == nil {
		t.Fatal("expected decrypt with wrong key to fail")
	}
}

func TestStreamDecryptBadHeader(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	bogus := bytes.NewReader([]byte("XXXXXXXX..."))
	var out bytes.Buffer
	if err := StreamDecrypt(bogus, &out, key); err == nil {
		t.Fatal("expected error on bad header")
	}
}

func TestStreamDecryptShortKey(t *testing.T) {
	var out bytes.Buffer
	if err := StreamDecrypt(bytes.NewReader(nil), &out, []byte("too short")); err == nil {
		t.Fatal("expected error on short key")
	}
}
