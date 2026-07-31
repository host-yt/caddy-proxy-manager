package handlers

import (
	"testing"
	"time"
)

// Both drivers must yield the same bucket key: MySQL returns time.Time under
// parseTime=true, SQLite returns TEXT.
func TestScanDayKey(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
		ok   bool
	}{
		{"mysql time.Time", time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC), "2026-07-31", true},
		{"sqlite text", "2026-07-31", "2026-07-31", true},
		{"sqlite datetime text", "2026-07-31 00:00:00", "2026-07-31", true},
		{"raw bytes", []byte("2026-07-31"), "2026-07-31", true},
		{"short", "2026-07", "", false},
		{"garbage", "not-a-date", "", false},
		{"nil", nil, "", false},
		{"int", int64(20260731), "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := scanDayKey(c.in)
			if ok != c.ok || got != c.want {
				t.Fatalf("scanDayKey(%v) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
			}
		})
	}
}
