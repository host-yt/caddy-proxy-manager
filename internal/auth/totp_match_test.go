package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestMatchTOTPReturnsProducingCounter(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_800_000_015, 0)
	cur := now.Unix() / 30
	for _, off := range []int64{-1, 0, 1} {
		code, err := totp.GenerateCode(secret, time.Unix((cur+off)*30, 0))
		if err != nil {
			t.Fatal(err)
		}
		got, err := MatchTOTP(secret, code, now)
		if err != nil || got != cur+off {
			t.Fatalf("offset %d: got counter %d err %v, want %d", off, got, err, cur+off)
		}
	}
	code, _ := totp.GenerateCode(secret, time.Unix((cur+2)*30, 0))
	if _, err := MatchTOTP(secret, code, now); err == nil {
		t.Fatal("code two steps ahead must be rejected")
	}
}
