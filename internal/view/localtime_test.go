package view

import (
	"testing"
	"time"
)

func TestLocalTime(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		t.Skip("no tzdata")
	}
	old := displayLoc
	displayLoc = func() *time.Location { return loc }
	defer func() { displayLoc = old }()
	f := CommonFuncs()["localTime"].(func(time.Time, string) string)
	got := f(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC), "15:04")
	if got != "11:00" {
		t.Fatalf("got %s", got)
	}
}
