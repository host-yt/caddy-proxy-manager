package security

import "testing"

func TestMTLSRBACToken_BindsNodeAndRoute(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	tok := MTLSRBACToken(key, 1, 7)
	if tok == "" {
		t.Fatal("empty token for valid input")
	}
	if !VerifyMTLSRBACToken(key, 1, 7, tok) {
		t.Fatal("valid token rejected")
	}
	if VerifyMTLSRBACToken(key, 2, 7, tok) {
		t.Error("token accepted for another node")
	}
	if VerifyMTLSRBACToken(key, 1, 8, tok) {
		t.Error("token accepted for another route")
	}
	if VerifyMTLSRBACToken([]byte("ffffffffffffffffffffffffffffffff"), 1, 7, tok) {
		t.Error("token accepted under another key")
	}
	// Ids are separated, so (1,17) and (11,7) must not collide.
	if MTLSRBACToken(key, 1, 17) == MTLSRBACToken(key, 11, 7) {
		t.Error("id concatenation is ambiguous")
	}
}

func TestMTLSRBACToken_RejectsMissingInput(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	if MTLSRBACToken(nil, 1, 7) != "" {
		t.Error("token issued without a key")
	}
	if MTLSRBACToken(key, 0, 7) != "" || MTLSRBACToken(key, 1, 0) != "" {
		t.Error("token issued for a zero id")
	}
	if VerifyMTLSRBACToken(key, 1, 7, "") {
		t.Error("empty token verified")
	}
	if VerifyMTLSRBACToken(nil, 1, 7, "anything") {
		t.Error("verification passed without a key")
	}
}
