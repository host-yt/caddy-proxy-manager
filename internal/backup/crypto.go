package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Stream encryption format:
//
//   header     "HPGBK1\0\0"            (8 bytes)
//   for each chunk while not EOF:
//       length (uint32 BE)             ciphertext length
//       nonce  (12 bytes)
//       ct     (length bytes)          AES-256-GCM(plaintext)
//
// Chunk plaintext is up to 1 MiB. Each chunk gets a fresh random nonce —
// safe because GCM nonce reuse is the only catastrophic failure mode for
// this construction; with 96-bit nonces from a CSPRNG, collisions are
// negligible up to ~2^32 chunks per key.
//
// Decoder reads header, then loops reading length+nonce+ct, decrypting
// in place, writing plaintext out.

const (
	streamHeader = "HPGBK1\x00\x00"
	chunkSize    = 1 << 20 // 1 MiB
)

type streamEncryptWriter struct {
	w       io.Writer
	gcm     cipher.AEAD
	buf     []byte
	written bool // header written?
	closed  bool
}

func newStreamEncryptWriter(w io.Writer, key []byte) (*streamEncryptWriter, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("backup: bad key length %d, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &streamEncryptWriter{w: w, gcm: gcm, buf: make([]byte, 0, chunkSize)}, nil
}

func (s *streamEncryptWriter) Write(p []byte) (int, error) {
	if s.closed {
		return 0, errors.New("write on closed stream")
	}
	if !s.written {
		if _, err := s.w.Write([]byte(streamHeader)); err != nil {
			return 0, err
		}
		s.written = true
	}
	total := 0
	for len(p) > 0 {
		room := chunkSize - len(s.buf)
		take := len(p)
		if take > room {
			take = room
		}
		s.buf = append(s.buf, p[:take]...)
		p = p[take:]
		total += take
		if len(s.buf) == chunkSize {
			if err := s.flushChunk(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

func (s *streamEncryptWriter) flushChunk() error {
	if len(s.buf) == 0 {
		return nil
	}
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := s.gcm.Seal(nil, nonce, s.buf, nil)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(ct)))
	if _, err := s.w.Write(lb[:]); err != nil {
		return err
	}
	if _, err := s.w.Write(nonce); err != nil {
		return err
	}
	if _, err := s.w.Write(ct); err != nil {
		return err
	}
	s.buf = s.buf[:0]
	return nil
}

func (s *streamEncryptWriter) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	if !s.written {
		// Empty stream: still emit header so decode works.
		if _, err := s.w.Write([]byte(streamHeader)); err != nil {
			return err
		}
	}
	return s.flushChunk()
}

// maxStreamChunkCT bounds a single chunk's ciphertext length. Our writer
// emits 1 MiB plaintext + 16 byte GCM tag per chunk, so 2 MiB is the
// natural upper bound. Cap at 4 MiB for headroom against future writers,
// but refuse anything larger so a tampered artifact cannot OOM the
// verify/restore path (security review P1).
const maxStreamChunkCT = 4 << 20

// StreamDecrypt decrypts a stream-encrypted backup from r into w using key.
// Exposed so a separate restore tool can decrypt artifacts off the panel.
func StreamDecrypt(r io.Reader, w io.Writer, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("backup: bad key length %d, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	hdr := make([]byte, len(streamHeader))
	if _, err := io.ReadFull(r, hdr); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if string(hdr) != streamHeader {
		return errors.New("bad backup header")
	}
	for {
		var lb [4]byte
		_, err := io.ReadFull(r, lb[:])
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(lb[:])
		if n > maxStreamChunkCT {
			return fmt.Errorf("chunk length %d exceeds cap %d (tampered?)", n, maxStreamChunkCT)
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(r, nonce); err != nil {
			return err
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(r, ct); err != nil {
			return err
		}
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return fmt.Errorf("decrypt chunk: %w", err)
		}
		if _, err := w.Write(pt); err != nil {
			return err
		}
	}
}
