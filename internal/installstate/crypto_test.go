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

// A scoped Manager must refuse a ciphertext sealed for a different purpose.
// Without this the domain separation is nominal: the envelope names its own
// sub-key, so a swapped-in value from another domain would decrypt cleanly
// (CRYPTO-02).
func TestScopedDecryptRejectsForeignPurpose(t *testing.T) {
	m := newTestMgr(t)
	wgSealed, err := m.EncryptFor("wg", "wg-private-key")
	if err != nil {
		t.Fatalf("EncryptFor: %v", err)
	}
	route := m.Scoped("route")
	if got, err := route.Decrypt(wgSealed); err == nil {
		t.Fatalf("route consumer decrypted a wg secret: %q", got)
	}
	// Its own purpose still roundtrips, and legacy ciphertext stays readable.
	own, err := route.Encrypt("route-secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got, err := route.Decrypt(own); err != nil || got != "route-secret" {
		t.Fatalf("own purpose Decrypt = %q, %v", got, err)
	}
	legacy, err := seal(m.key, "old-route-secret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if got, err := route.Decrypt(legacy); err != nil || got != "old-route-secret" {
		t.Fatalf("legacy Decrypt = %q, %v", got, err)
	}
}

// DeriveKey namespaces MAC key material away from the at-rest sub-keys.
func TestDeriveKey(t *testing.T) {
	m := newTestMgr(t)
	a, err := m.DeriveKey("mtls-rbac")
	if err != nil || len(a) != 32 {
		t.Fatalf("DeriveKey = %d bytes, %v", len(a), err)
	}
	b, _ := m.DeriveKey("something-else")
	if string(a) == string(b) {
		t.Error("different labels derived the same key")
	}
	purpose, _ := m.purposeKey("mtls-rbac")
	if string(a) == string(purpose) {
		t.Error("derive label collides with the at-rest purpose sub-key")
	}
	if _, err := m.DeriveKey(""); err == nil {
		t.Error("empty label accepted")
	}
	again, _ := m.DeriveKey("mtls-rbac")
	if string(a) != string(again) {
		t.Error("DeriveKey is not deterministic")
	}
}
