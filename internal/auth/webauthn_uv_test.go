package auth

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

// HPG-033: a passwordless assertion mints a full session audited as MFA, so it
// must require user verification. go-webauthn enforces UV only when the
// requirement is "required", and every Begin* call defaults to the config
// value - which used to be unset (i.e. "preferred", enforced nowhere).
func TestWebAuthnRequiresUserVerification(t *testing.T) {
	w, err := NewWebAuthn("https://panel.example.com", "HPG")
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	if got := w.Lib().Config.AuthenticatorSelection.UserVerification; got != protocol.VerificationRequired {
		t.Fatalf("config user verification = %q, want %q", got, protocol.VerificationRequired)
	}
	opts, sd, err := w.Lib().BeginDiscoverableLogin()
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	if opts.Response.UserVerification != protocol.VerificationRequired {
		t.Errorf("assertion options user verification = %q, want %q",
			opts.Response.UserVerification, protocol.VerificationRequired)
	}
	// The session copy is what FinishLogin checks the assertion against.
	if sd.UserVerification != protocol.VerificationRequired {
		t.Errorf("session user verification = %q, want %q",
			sd.UserVerification, protocol.VerificationRequired)
	}
}
