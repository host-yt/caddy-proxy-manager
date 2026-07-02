package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
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

// legacyEncrypt seals plain the way the old (pre-PROD-06) writer did: v1
// header, no AAD, single chunk. Used to verify the v1 decode path still works.
func legacyEncrypt(t *testing.T, key, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	var buf bytes.Buffer
	buf.WriteString(streamHeaderV1)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(ct)))
	buf.Write(lb[:])
	buf.Write(nonce)
	buf.Write(ct)
	return buf.Bytes()
}

// TestStreamDecryptLegacyV1 ensures backups written before PROD-06 still
// restore via the kept legacy decode path.
func TestStreamDecryptLegacyV1(t *testing.T) {
	key := bytes.Repeat([]byte{0x03}, 32)
	plain := []byte("legacy backup payload")
	artifact := legacyEncrypt(t, key, plain)
	var dec bytes.Buffer
	if err := StreamDecrypt(bytes.NewReader(artifact), &dec, key); err != nil {
		t.Fatalf("legacy decrypt: %v", err)
	}
	if !bytes.Equal(plain, dec.Bytes()) {
		t.Fatalf("legacy roundtrip mismatch: got %q", dec.Bytes())
	}
}

// TestStreamDecryptV2RejectsTruncation confirms a v2 stream cut off before
// its authenticated final-chunk marker fails instead of silently returning
// a partial (and, for an attacker, undetectable) restore.
func TestStreamDecryptV2RejectsTruncation(t *testing.T) {
	key := bytes.Repeat([]byte{0x04}, 32)
	plain := make([]byte, chunkSize+chunkSize/2) // forces 2 chunks: full + final
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	w, err := newStreamEncryptWriter(&enc, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	full := enc.Bytes()
	// Drop the final chunk's record so decode hits EOF before sawFinal.
	truncated := full[:len(full)-4-12-16]
	var dec bytes.Buffer
	if err := StreamDecrypt(bytes.NewReader(truncated), &dec, key); err == nil {
		t.Fatal("expected truncated v2 stream to fail decrypt")
	}
}

// TestStreamDecryptV2RejectsDuplicateChunk confirms a duplicated first
// chunk (replay of a valid ciphertext) fails AAD verification because its
// index no longer matches its stream position.
func TestStreamDecryptV2RejectsDuplicateChunk(t *testing.T) {
	key := bytes.Repeat([]byte{0x05}, 32)
	plain := make([]byte, chunkSize+16)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	w, err := newStreamEncryptWriter(&enc, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	full := enc.Bytes()
	// First record: header(8) + len(4) + nonce(12) + ct(chunkSize+16).
	firstRecLen := 4 + 12 + (chunkSize + 16)
	firstRec := full[8 : 8+firstRecLen]
	// Splice: header + firstRec + firstRec(again, now at wrong index) + rest.
	tampered := append([]byte{}, full[:8+firstRecLen]...)
	tampered = append(tampered, firstRec...)
	tampered = append(tampered, full[8+firstRecLen:]...)
	var dec bytes.Buffer
	if err := StreamDecrypt(bytes.NewReader(tampered), &dec, key); err == nil {
		t.Fatal("expected duplicated chunk to fail decrypt (AAD index mismatch)")
	}
}
