package handlers

import "testing"

func TestCounterDeltas(t *testing.T) {
	in := []trafficSample{
		{1, 0, 100, 1}, {1, 60, 110, 1}, {1, 120, 5, 0}, {1, 3600, 15, 2}, // reset, gap
		{2, 0, 50, 0}, {2, 60, 70, 0},
	}
	var req, errs uint64
	hr1 := uint64(0)
	for _, d := range counterDeltas(in) {
		req += d.Req
		errs += d.Err
		if d.Node == 1 && d.TS == 3600 {
			hr1 = d.Req
		}
	}
	if req != 10+5+10+20 || errs != 0+0+2+0 || hr1 != 10 {
		t.Fatalf("req=%d errs=%d hr1=%d", req, errs, hr1)
	}
}
