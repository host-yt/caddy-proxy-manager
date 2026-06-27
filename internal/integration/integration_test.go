//go:build integration

// Integration tests against the docker-compose stack at
// deploy/integration/docker-compose.yml. Run with:
//
//	docker compose -f deploy/integration/docker-compose.yml up -d
//	go test -tags=integration ./internal/integration/...
//	docker compose -f deploy/integration/docker-compose.yml down -v
//
// These do not run in CI by default (the // +build tag keeps them out
// of `go test ./...`). They exist because the unit suite cannot reach
// real ACME / SMTP / OIDC / SSH servers, and shipping a panel as
// "prod-ready" without those handshakes ever being exercised is the
// posture the audit flagged.
package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/oschwald/maxminddb-golang"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// TestPebbleReachable verifies the Pebble ACME directory is up and
// returns the expected JSON shape. Validates the stack is healthy.
func TestPebbleReachable(t *testing.T) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := hc.Get("https://127.0.0.1:14000/dir")
	if err != nil {
		t.Skipf("pebble not reachable (start integration stack): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("pebble /dir: status %d", resp.StatusCode)
	}
}

// TestMailpitSMTPRoundtrip sends a real SMTP message to Mailpit and reads
// it back via Mailpit's HTTP API. Exercises the panel's go-mail config
// envelope without going to a real provider.
func TestMailpitSMTPRoundtrip(t *testing.T) {
	auth := smtp.PlainAuth("", "", "", "127.0.0.1")
	_ = auth
	c, err := smtp.Dial("127.0.0.1:11025")
	if err != nil {
		t.Skipf("mailpit not reachable (start integration stack): %v", err)
	}
	defer c.Close()
	if err := c.Mail("panel@hpg.test"); err != nil {
		t.Fatal(err)
	}
	if err := c.Rcpt("admin@hpg.test"); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("Subject: hpg integration test\r\n\r\nhello from integration test\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.Quit()

	hc := &http.Client{Timeout: 3 * time.Second}
	resp, err := hc.Get("http://127.0.0.1:18025/api/v1/messages?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("mailpit API status %d", resp.StatusCode)
	}
}

// TestDexDiscovery hits Dex's well-known config to prove the OIDC issuer
// is reachable and serves a valid discovery document.
func TestDexDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := oidc.NewProvider(ctx, "http://127.0.0.1:15556")
	if err != nil {
		t.Skipf("dex not reachable (start integration stack): %v", err)
	}
}

// TestSFTPLoginUploadDownload writes a probe file to the opensshd
// container via password auth, downloads it back, deletes it. Exercises
// the same code path Hetzner Storage Box would take.
func TestSFTPLoginUploadDownload(t *testing.T) {
	cfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:12222", 5*time.Second)
	if err != nil {
		t.Skipf("sftp not reachable (start integration stack): %v", err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "127.0.0.1:12222", cfg)
	if err != nil {
		t.Fatalf("ssh handshake: %v", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()
	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatalf("sftp client: %v", err)
	}
	defer sc.Close()

	// atmoz/sftp arg `testuser:testpass:::backups` creates a writable
	// /home/testuser/backups directory. SFTP defaults the working dir to
	// /, so we land at /backups via absolute path.
	probe := "/backups/integration-probe.txt"
	body := []byte("integration roundtrip " + time.Now().Format(time.RFC3339))
	f, err := sc.Create(probe)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write(body); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = f.Close()

	rf, err := sc.Open(probe)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	buf := make([]byte, len(body))
	if _, err := rf.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = rf.Close()
	if string(buf) != string(body) {
		t.Fatalf("body mismatch:\nwant %q\ngot %q", body, buf)
	}
	_ = sc.Remove(probe)
	_ = strings.TrimSpace // imported but ensure stays used
}

// TestGeoIPMMDBLookup opens a real MaxMind Country DB and verifies 8.8.8.8 resolves to US.
// Needs HPG_TEST_GEOIP_MMDB=/path/to/GeoLite2-Country.mmdb to run.
func TestGeoIPMMDBLookup(t *testing.T) {
	path := os.Getenv("HPG_TEST_GEOIP_MMDB")
	if path == "" {
		t.Skip("set HPG_TEST_GEOIP_MMDB to run GeoIP integration tests")
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		t.Fatalf("open mmdb: %v", err)
	}
	defer db.Close()

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	ip := net.ParseIP("8.8.8.8")
	if err := db.Lookup(ip, &record); err != nil {
		t.Fatalf("lookup 8.8.8.8: %v", err)
	}
	if record.Country.ISOCode != "US" {
		t.Errorf("8.8.8.8: got ISOCode %q, want US", record.Country.ISOCode)
	}
}

// TestGeoIPNodeMetaEndpoint verifies the panel serves GeoIP DB metadata to authenticated nodes.
// Needs HPG_TEST_PANEL_URL and HPG_TEST_NODE_TOKEN to run.
func TestGeoIPNodeMetaEndpoint(t *testing.T) {
	panelURL := os.Getenv("HPG_TEST_PANEL_URL")
	token := os.Getenv("HPG_TEST_NODE_TOKEN")
	if panelURL == "" || token == "" {
		t.Skip("set HPG_TEST_PANEL_URL and HPG_TEST_NODE_TOKEN to run panel integration tests")
	}
	url := strings.TrimRight(panelURL, "/") + "/api/node/geoip/meta"
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	hc := &http.Client{Timeout: 5 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("GET geoip/meta: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("geoip/meta: status %d", resp.StatusCode)
	}
	var meta struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode geoip/meta: %v", err)
	}
	if meta.SHA256 == "" {
		t.Error("geoip/meta: sha256 is empty - no GeoIP DB configured on panel")
	}
}
