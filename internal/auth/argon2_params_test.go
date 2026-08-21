package auth

import (
	"errors"
	"strings"
	"testing"
)

// TestVerifyPassword_RejectsOutOfRangeParams: the parameters live inside the
// stored hash, so a corrupt row or a restored/imported hash decides an
// allocation and a work factor. t=0 and p=0 also panic inside argon2.IDKey.
func TestVerifyPassword_RejectsOutOfRangeParams(t *testing.T) {
	good, err := HashPassword("correct horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword(good, "correct horse"); err != nil {
		t.Fatalf("healthy hash rejected: %v", err)
	}
	if err := VerifyPassword(good, "wrong"); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("wrong password: got %v, want ErrPasswordMismatch", err)
	}

	parts := strings.Split(good, "$")
	swap := func(idx int, val string) string {
		p := append([]string(nil), parts...)
		p[idx] = val
		return strings.Join(p, "$")
	}
	bad := map[string]string{
		"zero time":       swap(3, "m=65536,t=0,p=2"),
		"huge time":       swap(3, "m=65536,t=9999,p=2"),
		"zero threads":    swap(3, "m=65536,t=3,p=0"),
		"4 GiB memory":    swap(3, "m=4194304,t=3,p=2"),
		"tiny memory":     swap(3, "m=1,t=3,p=2"),
		"wrong version":   swap(2, "v=13"),
		"short salt":      swap(4, "AAAA"),
		"short hash":      swap(5, "AAAA"),
		"absurd key size": swap(5, strings.Repeat("A", 400)),
	}
	for name, enc := range bad {
		t.Run(name, func(t *testing.T) {
			err := VerifyPassword(enc, "correct horse")
			if err == nil {
				t.Fatal("accepted an out-of-range hash")
			}
			if errors.Is(err, ErrPasswordMismatch) {
				t.Fatalf("reported as a password mismatch instead of a malformed hash: %v", err)
			}
		})
	}
}
