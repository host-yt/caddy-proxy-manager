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

// Stream encryption format (v2):
//
//   header     "HPGBK2\0\0"            (8 bytes)
//   for each chunk while not EOF:
//       length (uint32 BE)             ciphertext length
//       nonce  (12 bytes)
//       ct     (length bytes)          AES-256-GCM(plaintext, aad=chunkAAD)
//
// Chunk plaintext is up to 1 MiB. Each chunk gets a fresh random nonce —
// safe because GCM nonce reuse is the only catastrophic failure mode for
// this construction; with 96-bit nonces from a CSPRNG, collisions are
// negligible up to ~2^32 chunks per key.
//
// PROD-06: v1 sealed each chunk with no AAD binding its position or whether
// it was the last one, so chunks could be reordered/duplicated/dropped, or
// the stream truncated, without any integrity failure (EOF at any chunk
// boundary was treated as a clean end). v2 binds a monotonic chunk index +
// a final-chunk flag into the GCM AAD, and the decoder rejects EOF unless
// the final-chunk marker was authenticated. v1 artifacts still decode via
// the legacy path below (StreamDecrypt dispatches on the header magic).
//
// Decoder reads header, then loops reading length+nonce+ct, decrypting
// in place, writing plaintext out.

const (
	streamHeaderV1 = "HPGBK1\x00\x00"
	streamHeaderV2 = "HPGBK2\x00\x00"
	chunkSize      = 1 << 20 // 1 MiB
)

// chunkAAD encodes the chunk index (uint64 BE) + a final-chunk flag byte as
// GCM additional data, so a chunk can't be replayed at a different position
// and a truncated stream can't be mistaken for a complete one.
func chunkAAD(index uint64, final bool) []byte {
	aad := make([]byte, 9)
	binary.BigEndian.PutUint64(aad[:8], index)
	if final {
		aad[8] = 1
	}
	return aad
}

type streamEncryptWriter struct {
	w       io.Writer
	gcm     cipher.AEAD
	buf     []byte
	idx     uint64 // next chunk index to emit
	written bool   // header written?
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
		if _, err := s.w.Write([]byte(streamHeaderV2)); err != nil {
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
			// Not final: more Write calls may follow. Close() emits the
			// true final chunk (possibly empty) once the stream ends.
			if err := s.flushChunk(false); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

func (s *streamEncryptWriter) flushChunk(final bool) error {
	if len(s.buf) == 0 && !final {
		return nil
	}
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	aad := chunkAAD(s.idx, final)
	ct := s.gcm.Seal(nil, nonce, s.buf, aad)
	s.idx++
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
		if _, err := s.w.Write([]byte(streamHeaderV2)); err != nil {
			return err
		}
	}
	// Always emit a final chunk (empty if the buffer was just flushed by an
	// exact chunkSize Write) so the decoder has an authenticated end marker.
	return s.flushChunk(true)
}

// maxStreamChunkCT bounds a single chunk's ciphertext length. Our writer
// emits 1 MiB plaintext + 16 byte GCM tag per chunk, so 2 MiB is the
// natural upper bound. Cap at 4 MiB for headroom against future writers,
// but refuse anything larger so a tampered artifact cannot OOM the
// verify/restore path (security review P1).
const maxStreamChunkCT = 4 << 20

// StreamDecrypt decrypts a stream-encrypted backup from r into w using key.
// Exposed so a separate restore tool can decrypt artifacts off the panel.
// Dispatches on the header magic: v2 enforces chunk-index + final-marker
// AAD (PROD-06); v1 is kept as a legacy read-only path for old backups.
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
	hdr := make([]byte, len(streamHeaderV2))
	if _, err := io.ReadFull(r, hdr); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	switch string(hdr) {
	case streamHeaderV2:
		return streamDecryptV2(r, w, gcm)
	case streamHeaderV1:
		return streamDecryptV1(r, w, gcm)
	default:
		return errors.New("bad backup header")
	}
}

// streamDecryptV2 requires each chunk's AAD (index + final flag) to verify,
// and rejects EOF unless a final=true chunk was seen - a reordered,
// duplicated, dropped, or truncated stream fails closed instead of silently
// restoring partial/corrupt data.
func streamDecryptV2(r io.Reader, w io.Writer, gcm cipher.AEAD) error {
	var idx uint64
	sawFinal := false
	for {
		var lb [4]byte
		_, err := io.ReadFull(r, lb[:])
		if errors.Is(err, io.EOF) {
			if !sawFinal {
				return errors.New("truncated backup stream: no final-chunk marker")
			}
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
		if sawFinal {
			// Any chunk after the authenticated final marker is either a
			// replay/append or a corrupted stream - reject either way.
			return errors.New("backup stream: data after final-chunk marker")
		}
		// Try final=true first, then final=false: the AAD flag tells us
		// which one the sender meant, and a mismatch fails GCM auth anyway.
		pt, err := gcm.Open(nil, nonce, ct, chunkAAD(idx, true))
		if err == nil {
			sawFinal = true
		} else {
			pt, err = gcm.Open(nil, nonce, ct, chunkAAD(idx, false))
			if err != nil {
				return fmt.Errorf("decrypt chunk %d: %w", idx, err)
			}
		}
		if _, err := w.Write(pt); err != nil {
			return err
		}
		idx++
	}
}

// streamDecryptV1 is the legacy no-AAD decode path, kept so backups made
// before PROD-06 still restore. EOF at any chunk boundary is a clean end,
// same as the original behavior.
func streamDecryptV1(r io.Reader, w io.Writer, gcm cipher.AEAD) error {
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
