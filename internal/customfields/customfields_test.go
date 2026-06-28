package customfields

import (
	"net/url"
	"testing"
)

func TestEncodeFromFormValidation(t *testing.T) {
	defs := []Def{
		{Key: "company", Label: "Company", Type: Text, Required: true},
		{Key: "seats", Label: "Seats", Type: Number},
		{Key: "tier", Label: "Tier", Type: Select, Options: []string{"bronze", "gold"}},
		{Key: "vip", Label: "VIP", Type: Bool},
	}

	// Happy path.
	f := url.Values{"cf_company": {"Acme"}, "cf_seats": {"12"}, "cf_tier": {"gold"}, "cf_vip": {"1"}}
	js, err := EncodeFromForm(defs, f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := Decode(js)
	if m["company"] != "Acme" || m["seats"] != "12" || m["tier"] != "gold" || m["vip"] != "1" {
		t.Fatalf("roundtrip mismatch: %#v", m)
	}

	// Required text missing.
	if _, err := EncodeFromForm(defs, url.Values{"cf_seats": {"1"}}); err == nil {
		t.Error("expected error for missing required field")
	}
	// Number that is not numeric.
	if _, err := EncodeFromForm(defs, url.Values{"cf_company": {"A"}, "cf_seats": {"abc"}}); err == nil {
		t.Error("expected error for non-numeric number field")
	}
	// Select value outside options.
	if _, err := EncodeFromForm(defs, url.Values{"cf_company": {"A"}, "cf_tier": {"platinum"}}); err == nil {
		t.Error("expected error for invalid select option")
	}
	// Bool normalizes a junk value to empty.
	js, err = EncodeFromForm(defs, url.Values{"cf_company": {"A"}, "cf_vip": {"yes"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if Decode(js)["vip"] != "" {
		t.Error("bool junk value should normalize to empty")
	}
}

func TestDecodeNilSafe(t *testing.T) {
	if m := Decode(""); len(m) != 0 {
		t.Errorf("empty -> %#v, want empty map", m)
	}
	if m := Decode("{bad json"); len(m) != 0 {
		t.Errorf("bad json -> %#v, want empty map", m)
	}
}

func TestMergeOrdersByDefs(t *testing.T) {
	defs := []Def{{Key: "a", Label: "A", Type: Text}, {Key: "b", Label: "B", Type: Text}}
	views := Merge(defs, map[string]string{"a": "1"})
	if len(views) != 2 || views[0].Def.Key != "a" || views[0].Value != "1" || views[1].Value != "" {
		t.Fatalf("merge mismatch: %#v", views)
	}
}

func TestValidateKey(t *testing.T) {
	for _, ok := range []string{"company", "seat_count", "x1"} {
		if !ValidateKey(ok) {
			t.Errorf("ValidateKey(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "Company", "has space", "dash-no", "way_too_long_key_name_exceeding_forty_characters_limit"} {
		if ValidateKey(bad) {
			t.Errorf("ValidateKey(%q) = true, want false", bad)
		}
	}
}
