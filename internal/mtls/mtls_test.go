package mtls

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	certPEM, keyPEM, nb, na, err := generateCA("Test Root CA", defaultCAValidity)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	if !na.After(nb) {
		t.Fatalf("not_after %v should be after not_before %v", na, nb)
	}
	cert, key, err := parseCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCA round-trip: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("generated cert is not a CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("CA missing KeyUsageCertSign")
	}
	if cert.Subject.CommonName != "Test Root CA" {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}
	if key == nil {
		t.Fatal("nil CA key")
	}
}

func TestSignClientCertVerifiesAgainstCA(t *testing.T) {
	caCertPEM, caKeyPEM, _, _, err := generateCA("Issuer CA", defaultCAValidity)
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("parseCA: %v", err)
	}

	certPEM, keyPEM, na, err := signClientCert(caCert, caKey, "device-42", big.NewInt(7), defaultClientValidity)
	if err != nil {
		t.Fatalf("signClientCert: %v", err)
	}
	if time.Until(na) <= 0 {
		t.Fatalf("client cert already expired: %v", na)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("client cert PEM did not decode")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	if leaf.Subject.CommonName != "device-42" {
		t.Fatalf("client CN = %q", leaf.Subject.CommonName)
	}
	if leaf.SerialNumber.Int64() != 7 {
		t.Fatalf("serial = %d, want 7", leaf.SerialNumber.Int64())
	}

	// Must chain to the CA and carry client-auth EKU.
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("client cert failed to verify against CA: %v", err)
	}

	if block, _ := pem.Decode([]byte(keyPEM)); block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("client key PEM malformed")
	}
}

func TestIssuedCertStatusHelpers(t *testing.T) {
	active := IssuedCert{Status: StatusActive, NotAfter: time.Now().Add(time.Hour)}
	if active.Revoked() {
		t.Fatal("active cert reported revoked")
	}
	if active.Expired() {
		t.Fatal("future cert reported expired")
	}
	revoked := IssuedCert{Status: StatusRevoked, NotAfter: time.Now().Add(time.Hour), RevokedAt: sql.NullTime{Valid: true, Time: time.Now()}}
	if !revoked.Revoked() {
		t.Fatal("revoked cert not reported revoked")
	}
	old := IssuedCert{Status: StatusActive, NotAfter: time.Now().Add(-time.Hour)}
	if !old.Expired() {
		t.Fatal("past cert not reported expired")
	}
}

func TestCreateCARequiresCrypto(t *testing.T) {
	s := &Service{} // no Encrypt configured
	if _, err := s.CreateCA(t.Context(), CreateCAInput{Name: "x", CommonName: "x"}); err == nil {
		t.Fatal("expected error when crypto not configured")
	}
}
