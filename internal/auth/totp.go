package auth

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"image/png"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

// GenerateTOTP creates a fresh TOTP secret for `account` under issuer `issuer`.
// Returns the otpauth URL (for QR), the base32 secret (for backup), and a
// PNG QR code image as raw bytes.
func GenerateTOTP(issuer, account string) (otpauthURL, secret string, png []byte, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		SecretSize:  20,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
		Period:      30,
	})
	if err != nil {
		return "", "", nil, err
	}
	pngBytes, err := qrPNG(key.URL())
	if err != nil {
		return "", "", nil, err
	}
	return key.URL(), key.Secret(), pngBytes, nil
}

// ValidateTOTP returns nil when code is the current 30s code for secret.
func ValidateTOTP(secret, code string) error {
	code = strings.TrimSpace(code)
	if len(code) < 6 {
		return errors.New("code too short")
	}
	if !totp.Validate(code, secret) {
		return errors.New("invalid code")
	}
	return nil
}

// GenerateRecoveryCodes returns N human-readable recovery codes plus their
// Argon2id hashes for at-rest storage.
func GenerateRecoveryCodes(n int) (codes []string, hashes []string, err error) {
	codes = make([]string, 0, n)
	hashes = make([]string, 0, n)
	for i := 0; i < n; i++ {
		raw := make([]byte, 10) // 80 bits → 16 base32 chars
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, err
		}
		c := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
		// Pretty: 4-4-4-4 grouping
		pretty := fmt.Sprintf("%s-%s-%s-%s", c[0:4], c[4:8], c[8:12], c[12:16])
		h, err := HashPassword(pretty)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, pretty)
		hashes = append(hashes, h)
	}
	return codes, hashes, nil
}

func qrPNG(payload string) ([]byte, error) {
	q, err := qrcode.New(payload, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	img := q.Image(220)
	var buf strings.Builder
	bw := &byteWriter{s: &buf}
	if err := png.Encode(bw, img); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

type byteWriter struct{ s *strings.Builder }

func (b *byteWriter) Write(p []byte) (int, error) { return b.s.Write(p) }
