package routes

import (
	"context"
	"log/slog"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
)

// OPS-005: the geo gate follows the node's agent-reported mmdb presence, not
// the panel's filesystem; a node without the DB must not get the matcher.
func TestGeoGateFollowsNodeReportedDB(t *testing.T) {
	db := migratedSQLite(t)
	id := seedWP1(t, db, ", geo_mode, geo_countries", ", 'deny', 'CN'")
	svc := &Service{DB: db, Logger: slog.Default(), GeoModuleAvailable: true,
		PanelInternalHost: "panel", PanelInternalPort: 8080}

	for _, tc := range []struct {
		reported any
		want     bool
	}{
		{0, false},
		{1, true},
		{nil, geoip.HasCountryDB()}, // unreported: panel's own copy decides
	} {
		if _, err := db.Exec(`UPDATE caddy_nodes SET geoip_db_present = ? WHERE id = 1`, tc.reported); err != nil {
			t.Fatalf("set: %v", err)
		}
		r, ok, err := svc.buildOneRoute(context.Background(), 1, id)
		if err != nil || !ok {
			t.Fatalf("buildOneRoute: ok=%v err=%v", ok, err)
		}
		if r.GeoModuleAvailable != tc.want {
			t.Errorf("reported=%v: GeoModuleAvailable=%v, want %v", tc.reported, r.GeoModuleAvailable, tc.want)
		}
	}
}
