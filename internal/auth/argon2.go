package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id params. Tuned for ~150 ms on modern x86_64. Adjust if too slow.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// Accepted ranges for parameters read back out of an encoded hash. Wide enough
// to verify hashes made with other sane settings (including a future cost bump
// or an imported hash), narrow enough that no encoded value can make one login
// attempt allocate gigabytes or spin for minutes.
const (
	maxArgonTime    = 16
	minArgonMemory  = 8 * 1024    // 8 MiB
	maxArgonMemory  = 1024 * 1024 // 1 GiB, in KiB as the PHC string encodes it
	maxArgonThreads = 16
	minArgonSaltLen = 8
	minArgonKeyLen  = 16
	maxArgonKeyLen  = 64
)

var ErrPasswordMismatch = errors.New("password mismatch")

// HashPassword returns the PHC-encoded Argon2id hash.
// Format: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("empty password")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword returns nil on match.
func VerifyPassword(encoded, password string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("invalid hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return fmt.Errorf("parse version: %w", err)
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return fmt.Errorf("parse params: %w", err)
	}
	// Bound everything read out of the encoded hash before handing it to the
	// KDF. The parameters decide an allocation and a work factor, and
	// argon2.IDKey panics outright on t=0 or p=0 - so a corrupted row, a bad
	// restore, or a hash written by anything but HashPassword must be rejected
	// here rather than turning a login attempt into an OOM or a crash.
	if version != argon2.Version {
		return fmt.Errorf("unsupported argon2 version %d", version)
	}
	if time < 1 || time > maxArgonTime {
		return fmt.Errorf("argon2 time parameter out of range: %d", time)
	}
	if memory < minArgonMemory || memory > maxArgonMemory {
		return fmt.Errorf("argon2 memory parameter out of range: %d", memory)
	}
	if threads < 1 || threads > maxArgonThreads {
		return fmt.Errorf("argon2 parallelism out of range: %d", threads)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("decode hash: %w", err)
	}
	if len(salt) < minArgonSaltLen {
		return fmt.Errorf("argon2 salt too short: %d bytes", len(salt))
	}
	if len(want) < minArgonKeyLen || len(want) > maxArgonKeyLen {
		return fmt.Errorf("argon2 hash length out of range: %d bytes", len(want))
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}
