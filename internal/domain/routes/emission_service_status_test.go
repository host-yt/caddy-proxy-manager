package routes

import (
	"context"
	"log/slog"
	"testing"
)

// HPG-007: a suspended service must not reach the node even when its routes
// were left in a serving status by a path that only wrote services.status.
func TestSuspendedServiceIsNotEmitted(t *testing.T) {
	db := migratedSQLite(t)
	id := seedWP1(t, db, "", "")
	svc := &Service{DB: db, Logger: slog.Default(),
		PanelInternalHost: "panel", PanelInternalPort: 8080}

	_, ids, err := svc.buildRoutesForNode(context.Background(), 1)
	if err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	if len(ids) != 1 || ids[0] != id {
		t.Fatalf("active service must emit its route, got ids=%v", ids)
	}

	for _, status := range []string{"suspended", "terminated"} {
		if _, err := db.Exec(`UPDATE services SET status = ? WHERE id = 1`, status); err != nil {
			t.Fatalf("set %s: %v", status, err)
		}
		_, ids, err := svc.buildRoutesForNode(context.Background(), 1)
		if err != nil {
			t.Fatalf("buildRoutesForNode(%s): %v", status, err)
		}
		if len(ids) != 0 {
			t.Errorf("%s service still emitted routes %v", status, ids)
		}
	}
}
