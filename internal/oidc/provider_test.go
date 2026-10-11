package oidc

import "testing"

func TestValidateIssuerRequiresHTTPS(t *testing.T) {
	for _, bad := range []string{
		"http://localhost-idp.example.com/",
		"http://localhost/",
		"http://127.0.0.1/",
		"ftp://idp.example.com/",
		"https://10.0.0.1/",
	} {
		if validateIssuer(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := validateIssuer("https://idp.example.com/application/o/x/"); err != nil {
		t.Errorf("https issuer rejected: %v", err)
	}
}
