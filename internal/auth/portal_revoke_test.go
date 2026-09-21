package auth

import (
	"context"
	"testing"
)

// HPG-004: revoking a user only swept the panel's own namespaces, and a portal
// session serialises its user id under a different JSON key. Disabling an
// account therefore left a live portal session (up to 30 days with "remember").
func TestDestroyAllForUserCoversPortalSessions(t *testing.T) {
	f := newFakeRedis()
	m := &Manager{rdb: f}
	f.vals[sessionKeyPrefix+"panel"] = `{"user_id":7,"v":2}`
	f.vals[PortalSessionKeyPrefix+"portal"] = `{"u":7,"ep":3,"v":1}`
	f.vals[PortalSessionKeyPrefix+"other"] = `{"u":9,"ep":1,"v":1}`
	f.vals[legacySessionKeyPrefix+"legacy"] = `{"user_id":7}`

	n, err := m.DestroyAllForUser(context.Background(), 7)
	if err != nil {
		t.Fatalf("DestroyAllForUser: %v", err)
	}
	if n != 3 {
		t.Errorf("killed = %d, want 3 (panel + portal + legacy)", n)
	}
	if _, ok := f.vals[PortalSessionKeyPrefix+"portal"]; ok {
		t.Errorf("portal session survived the revoke")
	}
	if _, ok := f.vals[PortalSessionKeyPrefix+"other"]; !ok {
		t.Errorf("another user's portal session must be untouched")
	}
}

// A session whose owner cannot be decoded (legacy shape, id 0) must not be
// swept by a revoke for some other user.
func TestSessionOwnerNeverMatchesZero(t *testing.T) {
	var o sessionOwner
	if o.owns(0) {
		t.Errorf("an undecodable owner must not match user 0")
	}
}
