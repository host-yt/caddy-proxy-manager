package handlers

import (
	"context"
	"reflect"
	"testing"
)

func TestExpandNodeAddrs(t *testing.T) {
	lookup := func(_ context.Context, h string) ([]string, error) {
		return map[string][]string{"proxy.example.com": {"42.119.12.119"}}[h], nil
	}
	got := expandNodeAddrs(context.Background(), lookup, []string{"1.2.3.4", "proxy.example.com"}, "")
	if want := []string{"1.2.3.4", "42.119.12.119"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	got = expandNodeAddrs(context.Background(), lookup, nil, "proxy.example.com")
	if !reflect.DeepEqual(got, []string{"42.119.12.119"}) {
		t.Fatalf("hostname only: got %v", got)
	}
}
