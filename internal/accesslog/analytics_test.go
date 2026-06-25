package accesslog

import (
	"testing"
	"time"
)

func TestNormalizeAnalyticsLimit(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int
	}{
		{name: "default", limit: 0, want: defaultAnalyticsLimit},
		{name: "negative", limit: -1, want: defaultAnalyticsLimit},
		{name: "inside cap", limit: 25, want: 25},
		{name: "capped", limit: maxAnalyticsLimit + 1, want: maxAnalyticsLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeAnalyticsLimit(tt.limit); got != tt.want {
				t.Fatalf("normalizeAnalyticsLimit(%d) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}

func TestNormalizeAnalyticsRange(t *testing.T) {
	to := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)

	from, gotTo := normalizeAnalyticsRange(time.Time{}, to)
	if !gotTo.Equal(to) {
		t.Fatalf("to = %s, want %s", gotTo, to)
	}
	if want := to.Add(-defaultAnalyticsWindow); !from.Equal(want) {
		t.Fatalf("default from = %s, want %s", from, want)
	}

	from, _ = normalizeAnalyticsRange(to.Add(-maxAnalyticsWindow-time.Hour), to)
	if want := to.Add(-maxAnalyticsWindow); !from.Equal(want) {
		t.Fatalf("capped from = %s, want %s", from, want)
	}

	from, _ = normalizeAnalyticsRange(to, to)
	if want := to.Add(-defaultAnalyticsWindow); !from.Equal(want) {
		t.Fatalf("non-forward range from = %s, want %s", from, want)
	}
}

func TestNormalizeTrafficStep(t *testing.T) {
	if got := normalizeTrafficStep(0); got != defaultTrafficStep {
		t.Fatalf("zero step = %s, want %s", got, defaultTrafficStep)
	}
	if got := normalizeTrafficStep(time.Second); got != minTrafficStep {
		t.Fatalf("small step = %s, want %s", got, minTrafficStep)
	}
	if got := normalizeTrafficStep(15 * time.Minute); got != 15*time.Minute {
		t.Fatalf("valid step = %s, want 15m", got)
	}
}
