package wireguard

import (
	"encoding/base64"
	"testing"
)

func TestGeneratePresharedKeyRoundTrip(t *testing.T) {
	a, err := GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidPresharedKey(a) {
		t.Fatalf("generated key rejected by validator: %q", a)
	}
	raw, err := base64.StdEncoding.DecodeString(a)
	if err != nil || len(raw) != 32 {
		t.Fatalf("want 32 raw bytes, got %d (%v)", len(raw), err)
	}
	b, err := GeneratePresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("two generated keys are identical")
	}
}

func TestValidPresharedKeyRejects(t *testing.T) {
	good, _ := GeneratePresharedKey()
	for _, bad := range []string{
		"",
		good[:43],       // 43 chars
		good + "A",      // 45 chars
		good[:43] + "!", // right length, not base64
		base64.StdEncoding.EncodeToString(make([]byte, 31)), // decodes to 31 bytes
	} {
		if ValidPresharedKey(bad) {
			t.Errorf("invalid key accepted: %q", bad)
		}
	}
}
