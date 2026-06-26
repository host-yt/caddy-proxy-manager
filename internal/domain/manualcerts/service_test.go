package manualcerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// genSelfSigned generates a self-signed ECDSA cert + key PEM pair for tests.
func genSelfSigned(t *testing.T, cn string, sans []string, ips []net.IP) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     sans,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certBuf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyBuf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})
	return string(certBuf), string(keyBuf)
}

func TestParseCertAndKey_Valid(t *testing.T) {
	certPEM, keyPEM := genSelfSigned(t, "test.example.com",
		[]string{"test.example.com", "www.test.example.com"}, nil)

	leaf, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if leaf.Subject.CommonName != "test.example.com" {
		t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, "test.example.com")
	}
}

func TestParseCertAndKey_MismatchedKey(t *testing.T) {
	certPEM, _ := genSelfSigned(t, "a.example.com", nil, nil)
	_, differentKey := genSelfSigned(t, "b.example.com", nil, nil)

	_, err := parseCertAndKey(certPEM, differentKey)
	if err == nil {
		t.Fatal("expected error for mismatched key, got nil")
	}
}

func TestParseCertAndKey_EmptyCert(t *testing.T) {
	_, keyPEM := genSelfSigned(t, "x.example.com", nil, nil)
	_, err := parseCertAndKey("", keyPEM)
	if err == nil {
		t.Fatal("expected error for empty cert PEM")
	}
}

func TestParseCertAndKey_GarbagePEM(t *testing.T) {
	_, err := parseCertAndKey("not-a-pem", "also-not-a-pem")
	if err == nil {
		t.Fatal("expected error for garbage PEM")
	}
}

func TestSANStrings(t *testing.T) {
	certPEM, keyPEM := genSelfSigned(t, "san.example.com",
		[]string{"san.example.com", "alt.example.com"},
		[]net.IP{net.ParseIP("192.0.2.1")})

	leaf, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sans := sanStrings(leaf)
	// Expect 2 DNS + 1 IP.
	if len(sans) != 3 {
		t.Errorf("len(sans) = %d, want 3; got %v", len(sans), sans)
	}
}

func TestExpiryStatus(t *testing.T) {
	now := time.Now()
	cases := []struct {
		notAfter time.Time
		want     ExpiryStatus
	}{
		{now.Add(-time.Hour), StatusExpired},
		{now.Add(15 * 24 * time.Hour), StatusWarn},
		{now.Add(60 * 24 * time.Hour), StatusOK},
	}
	for _, c := range cases {
		r := Record{NotAfter: c.notAfter}
		if got := r.Expiry(); got != c.want {
			t.Errorf("notAfter=%v: got %q, want %q", c.notAfter, got, c.want)
		}
	}
}

func TestValidateChainPEM_Valid(t *testing.T) {
	certPEM, _ := genSelfSigned(t, "chain.example.com", nil, nil)
	if err := validateChainPEM(certPEM); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateChainPEM_Empty(t *testing.T) {
	// Empty chain is valid (optional field).
	if err := validateChainPEM(""); err != nil {
		t.Errorf("empty chain should be ok, got: %v", err)
	}
}

func TestValidateChainPEM_Garbage(t *testing.T) {
	if err := validateChainPEM("-----BEGIN GARBAGE-----\ndGVzdA==\n-----END GARBAGE-----"); err == nil {
		t.Fatal("expected error for wrong PEM block type")
	}
}
