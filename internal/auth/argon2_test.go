package auth

import "testing"

func TestPasswordRoundtrip(t *testing.T) {
	password := "correct horse battery staple 12345"
	h, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPassword(h, password); err != nil {
		t.Fatalf("verify ok password: %v", err)
	}
	if err := VerifyPassword(h, password+"x"); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestPasswordEmpty(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("expected empty password to error")
	}
}

func TestPasswordBadEncoding(t *testing.T) {
	if err := VerifyPassword("not-a-hash", "x"); err == nil {
		t.Fatal("expected bad encoding error")
	}
}
