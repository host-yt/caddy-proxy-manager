package routes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// mtlsTestCAPEM mints a throwaway self-signed CA so the built config carries a
// trust anchor Caddy would actually accept.
func mtlsTestCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "create-test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// seedMTLSCA inserts one CA row and returns its id.
func seedMTLSCA(t *testing.T, db *sql.DB, certPEM, status string) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO mtls_cas (name, common_name, cert_pem, key_pem_enc, not_before, not_after, status)
		 VALUES ('anchor', 'create-test-ca', ?, '', ?, ?, ?)`,
		certPEM, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), status)
	if err != nil {
		t.Fatalf("insert mtls_cas: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func newMTLSCreateSvc(t *testing.T, db *sql.DB) *Service {
	t.Helper()
	// A cancelled background context keeps the post-commit advanceRoute
	// goroutines (DNS probe + Caddy push) from doing work after the test.
	bg, cancel := context.WithCancel(context.Background())
	cancel()
	return &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), BgCtx: bg}
}

// TestCreate_PersistsMTLS is the regression for the silent-discard bug: the
// create handler validated require_client_cert and then never wrote it, so a
// host the operator asked to lock came up serving anyone.
func TestCreate_PersistsMTLS(t *testing.T) {
	db := newPushTestDB(t)
	nodeID := seedCapacityFixture(t, db, 10)
	caPEM := mtlsTestCAPEM(t)
	caID := seedMTLSCA(t, db, caPEM, "active")

	svc := newMTLSCreateSvc(t, db)
	routeID, err := svc.Create(context.Background(), 0, CreateInput{
		ServiceID:         1,
		UpstreamPort:      10001,
		Domain:            "locked.example",
		SSL:               true,
		RequireClientCert: true,
		MTLSCAID:          caID,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	var gotFlag int
	var gotCA sql.NullInt64
	if err := db.QueryRow(
		"SELECT require_client_cert, mtls_ca_id FROM routes WHERE id = ?", routeID,
	).Scan(&gotFlag, &gotCA); err != nil {
		t.Fatalf("read route: %v", err)
	}
	if gotFlag != 1 {
		t.Errorf("require_client_cert = %d, want 1 (create silently dropped it)", gotFlag)
	}
	if !gotCA.Valid || gotCA.Int64 != caID {
		t.Errorf("mtls_ca_id = %v, want %d", gotCA, caID)
	}

	// Only serving routes are emitted; advanceRoute is stubbed out here.
	if _, err := db.Exec("UPDATE routes SET status = 'active' WHERE id = ?", routeID); err != nil {
		t.Fatal(err)
	}
	// The route must reach the node as an enforced one, with the anchor.
	built, ids, err := svc.buildRoutesForNode(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	var r caddyapi.Route
	for i, id := range ids {
		if id == routeID {
			r = built[i]
		}
	}
	if !r.RequireClientCert {
		t.Fatal("built route must require a client cert")
	}
	if r.MTLSCACertPEM != caPEM {
		t.Error("built route must carry the selected CA's certificate")
	}

	// End to end: the emitted Caddy config must carry the client-auth policy.
	cfg, _ := json.Marshal(caddyapi.BuildNodeConfig(built, caddyapi.NodeSettings{}))
	for _, want := range []string{`"client_authentication"`, `"require_and_verify"`, `"trusted_ca_certs"`} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("config is missing %s", want)
		}
	}
}

// TestCreate_RejectsMTLSWithoutUsableCA proves the enforcement flag is never
// stored without an anchor that can actually be emitted - the create must fail
// loudly instead of producing a host that looks locked and is not.
func TestCreate_RejectsMTLSWithoutUsableCA(t *testing.T) {
	db := newPushTestDB(t)
	seedCapacityFixture(t, db, 10)
	revokedCA := seedMTLSCA(t, db, mtlsTestCAPEM(t), "revoked")

	cases := map[string]int64{
		"no CA selected": 0,
		"inactive CA":    revokedCA,
		"unknown CA":     424242,
	}
	svc := newMTLSCreateSvc(t, db)
	for name, caID := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := svc.Create(context.Background(), 0, CreateInput{
				ServiceID: 1, UpstreamPort: 10002, Domain: "reject.example",
				SSL: true, RequireClientCert: true, MTLSCAID: caID,
			})
			if !errors.Is(err, ErrMTLSCAUnusable) {
				t.Fatalf("err = %v, want ErrMTLSCAUnusable", err)
			}
			var n int
			if err := db.QueryRow("SELECT COUNT(*) FROM routes WHERE domain = 'reject.example'").Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Errorf("%d route(s) created despite the rejection", n)
			}
		})
	}
}

// TestCreate_RejectsMTLSWithoutTLS: the client-auth policy is emitted as part
// of the route's TLS connection policy, so enforcement with SSL off produces
// either a wide-open host (fail_open) or a permanent 503 - while the panel
// records it as requiring client certificates. Both the submitted value and
// the one the plan gate forces must be refused.
func TestCreate_RejectsMTLSWithoutTLS(t *testing.T) {
	cases := map[string]struct {
		ssl     bool
		planSSL bool
	}{
		"SSL unchecked on the form":   {ssl: false, planSSL: true},
		"plan forces SSL off":         {ssl: true, planSSL: false},
		"neither form nor plan allow": {ssl: false, planSSL: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			db := newPushTestDB(t)
			seedCapacityFixture(t, db, 10)
			caID := seedMTLSCA(t, db, mtlsTestCAPEM(t), "active")
			if !tc.planSSL {
				if _, err := db.Exec("UPDATE plans SET ssl_enabled = 0 WHERE id = 1"); err != nil {
					t.Fatal(err)
				}
			}

			_, err := newMTLSCreateSvc(t, db).Create(context.Background(), 0, CreateInput{
				ServiceID: 1, UpstreamPort: 10004, Domain: "plaintext.example",
				SSL: tc.ssl, RequireClientCert: true, MTLSCAID: caID,
			})
			if !errors.Is(err, ErrMTLSNeedsTLS) {
				t.Fatalf("err = %v, want ErrMTLSNeedsTLS", err)
			}
			var n int
			if err := db.QueryRow("SELECT COUNT(*) FROM routes WHERE domain = 'plaintext.example'").Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Errorf("%d route(s) created despite the rejection", n)
			}
		})
	}
}

// TestCreate_ClearsAnchorWhenEnforcementOff: an mtls_ca_id with the flag off is
// dead state that a later toggle would silently activate.
func TestCreate_ClearsAnchorWhenEnforcementOff(t *testing.T) {
	db := newPushTestDB(t)
	seedCapacityFixture(t, db, 10)
	caID := seedMTLSCA(t, db, mtlsTestCAPEM(t), "active")

	routeID, err := newMTLSCreateSvc(t, db).Create(context.Background(), 0, CreateInput{
		ServiceID: 1, UpstreamPort: 10003, Domain: "open.example",
		SSL: true, RequireClientCert: false, MTLSCAID: caID,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var flag int
	var gotCA sql.NullInt64
	if err := db.QueryRow(
		"SELECT require_client_cert, mtls_ca_id FROM routes WHERE id = ?", routeID,
	).Scan(&flag, &gotCA); err != nil {
		t.Fatal(err)
	}
	if flag != 0 || gotCA.Valid {
		t.Errorf("want flag=0 ca=NULL, got flag=%d ca=%v", flag, gotCA)
	}
}

// TestCreate_RejectsWhenCALookupFails: the CA lookup is a prerequisite read.
// If it fails, the create must reject - treating a failed read as "nothing to
// worry about" is exactly how the sibling API path let enforcement and TLS
// drift apart.
func TestCreate_RejectsWhenCALookupFails(t *testing.T) {
	db := newPushTestDB(t)
	seedCapacityFixture(t, db, 10)
	if _, err := db.Exec("DROP TABLE mtls_cas"); err != nil {
		t.Fatalf("drop mtls_cas: %v", err)
	}

	_, err := newMTLSCreateSvc(t, db).Create(context.Background(), 0, CreateInput{
		ServiceID: 1, UpstreamPort: 10005, Domain: "readfail.example",
		SSL: true, RequireClientCert: true, MTLSCAID: 1,
	})
	if !errors.Is(err, ErrMTLSCAUnusable) {
		t.Fatalf("err = %v, want ErrMTLSCAUnusable", err)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM routes WHERE domain = 'readfail.example'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d route(s) created despite the failed lookup", n)
	}
}

// cleartextRedirectFor reports whether the built node config redirects plain
// HTTP for the host instead of proxying it: BuildRoute wraps the handlers in
// a subroute whose protocol=http branch answers 308.
func cleartextRedirectFor(cfg []byte, host string) bool {
	return strings.Contains(string(cfg),
		`{"handle":[{"handler":"static_response","headers":{"Location":["https://{http.request.host}{http.request.uri}"]},"status_code":308}],"match":[{"host":["`+host+`"],"protocol":"http"}]}`)
}

// TestCreate_MTLSImpliesForceHTTPS: mTLS lives in the TLS handshake and the
// node also listens on :80, so an enforced host must never be reachable in
// the clear. The create stores force_https=1 whatever was submitted, and the
// config built from the row redirects cleartext.
func TestCreate_MTLSImpliesForceHTTPS(t *testing.T) {
	db := newPushTestDB(t)
	nodeID := seedCapacityFixture(t, db, 10)
	caID := seedMTLSCA(t, db, mtlsTestCAPEM(t), "active")

	svc := newMTLSCreateSvc(t, db)
	routeID, err := svc.Create(context.Background(), 0, CreateInput{
		ServiceID: 1, UpstreamPort: 10006, Domain: "clear.example",
		SSL: true, ForceHTTPS: false, RequireClientCert: true, MTLSCAID: caID,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var fh int
	if err := db.QueryRow("SELECT force_https FROM routes WHERE id = ?", routeID).Scan(&fh); err != nil {
		t.Fatal(err)
	}
	if fh != 1 {
		t.Errorf("force_https = %d, want 1 on an mTLS route", fh)
	}
	if _, err := db.Exec("UPDATE routes SET status = 'active' WHERE id = ?", routeID); err != nil {
		t.Fatal(err)
	}
	built, _, err := svc.buildRoutesForNode(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	cfg, _ := json.Marshal(caddyapi.BuildNodeConfig(built, caddyapi.NodeSettings{}))
	if !cleartextRedirectFor(cfg, "clear.example") {
		t.Errorf("config proxies the mTLS host in the clear:\n%s", cfg)
	}
}

// TestBuild_MTLSRowWithForceHTTPSOffStillRedirects is the proof that the
// invariant does not depend on any write path: a row that reached the
// bypassed state by whatever route (older release, restore, hand edit, a
// writer nobody listed) is still served HTTPS-only, because the redirect is
// derived when the config is built.
func TestBuild_MTLSRowWithForceHTTPSOffStillRedirects(t *testing.T) {
	db := newPushTestDB(t)
	nodeID := seedCapacityFixture(t, db, 10)
	caID := seedMTLSCA(t, db, mtlsTestCAPEM(t), "active")

	svc := newMTLSCreateSvc(t, db)
	routeID, err := svc.Create(context.Background(), 0, CreateInput{
		ServiceID: 1, UpstreamPort: 10007, Domain: "legacy.example",
		SSL: true, RequireClientCert: true, MTLSCAID: caID,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// The state round 4 found, written behind every guard's back.
	if _, err := db.Exec("UPDATE routes SET status = 'active', force_https = 0 WHERE id = ?", routeID); err != nil {
		t.Fatal(err)
	}
	built, _, err := svc.buildRoutesForNode(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("buildRoutesForNode: %v", err)
	}
	cfg, _ := json.Marshal(caddyapi.BuildNodeConfig(built, caddyapi.NodeSettings{}))
	if !cleartextRedirectFor(cfg, "legacy.example") {
		t.Errorf("a stored force_https=0 exposed the mTLS backend on :80:\n%s", cfg)
	}
	if !strings.Contains(string(cfg), `"client_authentication"`) {
		t.Error("client-auth policy missing alongside the redirect")
	}
}
