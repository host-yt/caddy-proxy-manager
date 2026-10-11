package handlers

import (
	"context"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestPasskeyConsumeSingleUse(t *testing.T) {
	rdb := portalTestRedis(t)
	h := &PasskeyHandlers{RDB: rdb}
	ctx := context.Background()
	ticket, err := h.stash(ctx, "wa:test:", &webauthn.SessionData{Challenge: "c"})
	if err != nil {
		t.Fatal(err)
	}
	var sd webauthn.SessionData
	if err := h.consume(ctx, "wa:test:"+ticket, &sd); err != nil || sd.Challenge != "c" {
		t.Fatalf("first consume: %v %q", err, sd.Challenge)
	}
	if err := h.consume(ctx, "wa:test:"+ticket, &sd); err == nil {
		t.Fatal("second consume must fail")
	}
}
