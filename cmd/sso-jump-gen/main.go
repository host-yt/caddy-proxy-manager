// sso-jump-gen generates a signed SSO jump URL for testing the /auth/sso/jump
// endpoint without needing a running FOSSBilling instance.
//
// Usage:
//
//	go run ./cmd/sso-jump-gen \
//	  -secret=<128-char-hex> \
//	  -email=user@example.com \
//	  -base=https://proxy.example.com \
//	  -ttl=60
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"
)

func main() {
	secret := flag.String("secret", "", "128-char hex shared secret (from Admin → Settings → SSO Jump)")
	email := flag.String("email", "", "customer email address")
	base := flag.String("base", "https://proxy.example.com", "panel base URL (no trailing slash)")
	ttl := flag.Int("ttl", 60, "token lifetime in seconds (max 600)")
	flag.Parse()

	if *secret == "" || *email == "" {
		fmt.Fprintln(os.Stderr, "usage: sso-jump-gen -secret=HEX -email=user@example.com [-base=URL] [-ttl=60]")
		os.Exit(1)
	}
	if *ttl <= 0 || *ttl > 600 {
		fmt.Fprintln(os.Stderr, "error: ttl must be 1–600 seconds")
		os.Exit(1)
	}

	exp := time.Now().Unix() + int64(*ttl)
	message := fmt.Sprintf("email=%s&exp=%d", url.QueryEscape(*email), exp)
	mac := hmac.New(sha256.New, []byte(*secret))
	mac.Write([]byte(message))
	sig := hex.EncodeToString(mac.Sum(nil))

	jumpURL := fmt.Sprintf("%s/auth/sso/jump?email=%s&exp=%d&sig=%s",
		*base,
		url.QueryEscape(*email),
		exp,
		sig,
	)

	fmt.Println(jumpURL)
	fmt.Fprintf(os.Stderr, "expires: %s (in %d s)\n",
		time.Unix(exp, 0).UTC().Format(time.RFC3339), *ttl)
}
