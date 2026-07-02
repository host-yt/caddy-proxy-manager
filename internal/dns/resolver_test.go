package dns

import (
	"os"
	"reflect"
	"testing"
)

func TestWithDNSPort(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":                   "1.1.1.1:53",
		"8.8.8.8:53":                "8.8.8.8:53",
		"1.1.1.1:5353":              "1.1.1.1:5353",
		"::1":                       "[::1]:53",
		"[2606:4700:4700::1111]:53": "[2606:4700:4700::1111]:53",
	}
	for in, want := range cases {
		if got := withDNSPort(in); got != want {
			t.Errorf("withDNSPort(%q)=%q want %q", in, got, want)
		}
	}
}

func TestBootstrapResolvers(t *testing.T) {
	t.Setenv("HPG_DNS_RESOLVERS", " 9.9.9.9 , 1.0.0.1:53 ,")
	if got, want := bootstrapResolvers(), []string{"9.9.9.9:53", "1.0.0.1:53"}; !reflect.DeepEqual(got, want) {
		t.Errorf("override: got %v want %v", got, want)
	}
	os.Unsetenv("HPG_DNS_RESOLVERS")
	if got := bootstrapResolvers(); len(got) != 2 || got[0] != "1.1.1.1:53" {
		t.Errorf("default: got %v", got)
	}
}
