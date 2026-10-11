package store

import (
	"testing"
	"time"
)

func TestNullTimeScan(t *testing.T) {
	want := time.Date(2026, 10, 11, 16, 2, 44, 0, time.UTC)
	for _, src := range []any{"2026-10-11 16:02:44", []byte("2026-10-11 16:02:44"), want} {
		var n NullTime
		if err := n.Scan(src); err != nil || !n.Valid || !n.Time.Equal(want) {
			t.Fatalf("Scan(%T) = %+v, %v", src, n, err)
		}
	}
	var n NullTime
	if err := n.Scan(nil); err != nil || n.Valid {
		t.Fatalf("Scan(nil) = %+v, %v", n, err)
	}
}
