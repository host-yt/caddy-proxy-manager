package routes

import (
	"testing"
	"time"
)

func TestRTTBucketStart(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"2026-07-14T10:00:00Z", "2026-07-14T10:00:00Z"},
		{"2026-07-14T10:04:59Z", "2026-07-14T10:00:00Z"},
		{"2026-07-14T10:05:00Z", "2026-07-14T10:05:00Z"},
		{"2026-07-14T10:09:59Z", "2026-07-14T10:05:00Z"},
		{"2026-07-14T10:29:01Z", "2026-07-14T10:25:00Z"},
	}
	for _, c := range cases {
		in, err := time.Parse(time.RFC3339, c.in)
		if err != nil {
			t.Fatalf("parse %s: %v", c.in, err)
		}
		want, err := time.Parse(time.RFC3339, c.want)
		if err != nil {
			t.Fatalf("parse %s: %v", c.want, err)
		}
		if got := rttBucketStart(in); !got.Equal(want) {
			t.Errorf("rttBucketStart(%s) = %s, want %s", c.in, got, want)
		}
	}
}

func TestRTTBucketStartNonUTCInput(t *testing.T) {
	// A non-UTC input must be normalized before truncation, or the bucket
	// boundary would silently shift with the local offset.
	loc := time.FixedZone("UTC+2", 2*60*60)
	in := time.Date(2026, 7, 14, 12, 7, 0, 0, loc) // 10:07 UTC
	want := time.Date(2026, 7, 14, 10, 5, 0, 0, time.UTC)
	if got := rttBucketStart(in); !got.Equal(want) {
		t.Errorf("rttBucketStart(%s) = %s, want %s", in, got, want)
	}
}

func TestFoldRTTSampleFirstSample(t *testing.T) {
	got := foldRTTSample(rttStats{}, 42)
	want := rttStats{Avg: 42, Min: 42, Max: 42, Samples: 1}
	if got != want {
		t.Errorf("foldRTTSample(zero, 42) = %+v, want %+v", got, want)
	}
}

func TestFoldRTTSampleIncrementalAverage(t *testing.T) {
	// Fold three samples one at a time and confirm the running average
	// matches the plain arithmetic mean at each step.
	stats := rttStats{}
	samples := []int{10, 20, 30}
	wantAvgs := []int{10, 15, 20} // exact means: 10, 15, 20
	for i, s := range samples {
		stats = foldRTTSample(stats, s)
		if stats.Avg != wantAvgs[i] {
			t.Errorf("after sample %d: avg = %d, want %d", i, stats.Avg, wantAvgs[i])
		}
	}
	if stats.Samples != 3 {
		t.Errorf("samples = %d, want 3", stats.Samples)
	}
}

func TestFoldRTTSampleMinMax(t *testing.T) {
	stats := rttStats{}
	for _, s := range []int{50, 10, 90, 30} {
		stats = foldRTTSample(stats, s)
	}
	if stats.Min != 10 {
		t.Errorf("min = %d, want 10", stats.Min)
	}
	if stats.Max != 90 {
		t.Errorf("max = %d, want 90", stats.Max)
	}
	if stats.Samples != 4 {
		t.Errorf("samples = %d, want 4", stats.Samples)
	}
}

func TestFoldRTTSampleManySamplesStayBounded(t *testing.T) {
	// A long-running bucket (many probes before rotation) must not overflow
	// or drift - the incremental formula should converge to the true mean.
	stats := rttStats{}
	sum := 0
	n := 1000
	for i := 1; i <= n; i++ {
		v := 100 + i%50 // bounded oscillating values
		sum += v
		stats = foldRTTSample(stats, v)
	}
	wantAvg := sum / n
	// Incremental integer division can drift by a few ms from the exact
	// mean over many folds; assert it stays close rather than exact.
	diff := stats.Avg - wantAvg
	if diff < -2 || diff > 2 {
		t.Errorf("avg = %d, want close to %d (diff %d)", stats.Avg, wantAvg, diff)
	}
	if stats.Samples != n {
		t.Errorf("samples = %d, want %d", stats.Samples, n)
	}
}
