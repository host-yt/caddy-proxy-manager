package installstate

import "testing"

const testSecret = "test-app-secret-at-least-32-bytes-long!!"

func newTestMgr(t *testing.T) *Manager {
	t.Helper()
	m, err := New(t.TempDir(), testSecret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// Legacy shared-key roundtrip still works (back-compat).
func TestEncryptDecryptLegacyRoundtrip(t *testing.T) {
	m := newTestMgr(t)
	enc, err := m.Encrypt("hunter2")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(enc) >= len(v2Prefix) && enc[:len(v2Prefix)] == v2Prefix {
		t.Fatalf("unscoped Encrypt must not emit a v2 envelope: %q", enc)
	}
	got, err := m.Decrypt(enc)
	if err != nil || got != "hunter2" {
		t.Fatalf("Decrypt legacy = %q, %v", got, err)
	}
}

// A purpose-scoped Manager emits a v2 envelope and roundtrips.
func TestScopedEncryptRoundtrip(t *testing.T) {
	m := newTestMgr(t)
	wg := m.Scoped("wg")
	enc, err := wg.Encrypt("privkey")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	want := v2Prefix + "wg:"
	if len(enc) < len(want) || enc[:len(want)] != want {
		t.Fatalf("scoped Encrypt = %q, want prefix %q", enc, want)
	}
	// Both the scoped and the base Manager can read it (shared base key).
	if got, err := wg.Decrypt(enc); err != nil || got != "privkey" {
		t.Fatalf("scoped Decrypt = %q, %v", got, err)
	}
	if got, err := m.Decrypt(enc); err != nil || got != "privkey" {
		t.Fatalf("base Decrypt of v2 = %q, %v", got, err)
	}
}

// Different purposes derive independent keys: a value sealed for one purpose
// must not decrypt under another.
func TestPurposeKeyIsolation(t *testing.T) {
	m := newTestMgr(t)
	enc, err := m.EncryptFor("wg", "secret")
	if err != nil {
		t.Fatalf("EncryptFor: %v", err)
	}
	// Tamper the embedded purpose so the payload is opened with the wrong key.
	forged := v2Prefix + "mtls:" + enc[len(v2Prefix+"wg:"):]
	if _, err := m.Decrypt(forged); err == nil {
		t.Fatal("decrypt with mismatched purpose must fail (auth), got nil error")
	}
}

// The base Manager still decrypts legacy ciphertext after the v2 change.
func TestDecryptLegacyAfterUpgrade(t *testing.T) {
	m := newTestMgr(t)
	// Seal directly with the base key (legacy format, no prefix).
	legacy, err := seal(m.key, "old-value")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := m.Decrypt(legacy)
	if err != nil || got != "old-value" {
		t.Fatalf("Decrypt legacy = %q, %v", got, err)
	}
}

func TestDecryptMalformedV2(t *testing.T) {
	m := newTestMgr(t)
	for _, bad := range []string{"v2:", "v2:onlypurpose", "v2::payload"} {
		if _, err := m.Decrypt(bad); err == nil {
			t.Fatalf("Decrypt(%q) = nil error, want failure", bad)
		}
	}
}
