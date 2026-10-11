package accesslog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
)

// maxIngestBody caps the request body. Caddy nodes batch NDJSON; 8 MiB is far
// above any sane batch and stops a hostile caller pinning memory.
const maxIngestBody = 8 << 20

// caddyLogLine is the subset of Caddy's structured access-log JSON we care
// about. Caddy emits one JSON object per request when using the "json" encoder.
// Field names match Caddy v2's log output format.
type caddyLogLine struct {
	TS      float64     `json:"ts"` // Unix timestamp (fractional seconds)
	Request caddyLogReq `json:"request"`
	Status  int         `json:"status"`
	// duration is in fractional seconds; Caddy uses "duration" not "latency".
	Duration float64 `json:"duration"`
	// Size is response bytes as logged by Caddy's access log handler.
	Size int64 `json:"size"`
	// BytesRead is the request body bytes read by Caddy (emitted when > 0).
	BytesRead int64 `json:"bytes_read"`
}

type caddyLogReq struct {
	Method string `json:"method"`
	URI    string `json:"uri"`
	// Proto is the HTTP protocol version, e.g. "HTTP/1.1", "HTTP/2.0".
	Proto string `json:"proto"`
	// Caddy logs the request host and client IP as top-level fields on
	// "request", NOT inside headers. client_ip is the real client (after
	// trusted-proxy resolution); remote_ip is the raw socket peer.
	Host       string              `json:"host"`
	ClientIP   string              `json:"client_ip"`
	RemoteIP   string              `json:"remote_ip"`
	RemoteAddr string              `json:"remote_addr"`
	Headers    map[string][]string `json:"headers"`
}

// IngestHandler is the HTTP handler mounted at POST /internal/access-log.
// Caddy nodes POST one JSON object per line (NDJSON) or a single object.
// We resolve the route by matching the Host header the node recorded.
type IngestHandler struct {
	Store  *Store
	Broker *Broker
	Logger *slog.Logger
	// ResolveRoutes loads the routes the authenticated node serves. Every log
	// line is attributed through this index, so a node can only write history
	// for its own routes (LOG-01). Required; if nil the batch is dropped.
	ResolveRoutes func(ctx context.Context, nodeID int64) (NodeRouteIndex, error)
	// AuthNode validates a node agent token (Bearer) and returns the node id it
	// belongs to. The /internal/access-log route is reachable on the public app
	// port, so every POST must carry a valid per-node token or it is rejected.
	// Required; if nil all calls 401.
	AuthNode func(ctx context.Context, token string) (int64, bool)
}

func (h *IngestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Just under the node agent's 10s request timeout: the batch is one transaction.
	ctx, cancel := context.WithTimeout(r.Context(), 9*time.Second)
	defer cancel()

	// Authenticate the node agent. The endpoint is publicly reachable, so an
	// unauthenticated caller must not be able to inject/poison host logs.
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" || h.AuthNode == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nodeID, ok := h.AuthNode(ctx, token)
	if !ok || nodeID <= 0 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Resolve the node's own routes once per batch. A node that serves nothing
	// (or an index we cannot load) has nothing to attribute: drop the batch
	// instead of falling back to a global domain lookup, which is exactly the
	// cross-node/cross-tenant poisoning path this replaces.
	if h.ResolveRoutes == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	idx, err := h.ResolveRoutes(ctx, nodeID)
	if err != nil {
		h.Logger.Warn("accesslog route index", "node_id", nodeID, "err", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxIngestBody)
	// Scan line-by-line: each NDJSON line is decoded independently so a single
	// malformed/truncated line is skipped, not the rest of the batch (a shared
	// json.Decoder loses position on a syntax error and would drop everything
	// after it). Non-access log lines (no Host) are ignored downstream.
	sc := bufio.NewScanner(r.Body)
	// Line cap = body cap, so no line inside an accepted body is ever dropped.
	sc.Buffer(make([]byte, 0, 64*1024), maxIngestBody)
	var batch []Entry
	for sc.Scan() {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var line caddyLogLine
		if err := json.Unmarshal(b, &line); err != nil {
			continue // skip malformed line, keep ingesting the rest
		}
		if e, ok := toEntry(idx, line); ok {
			batch = append(batch, e)
		}
	}
	// Any non-2xx makes the agent resend the whole batch; nothing is stored
	// unless everything is, so the retry cannot double count.
	if err := sc.Err(); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if err := h.Store.InsertBatch(ctx, batch); err != nil {
		h.Logger.Warn("accesslog insert", "node_id", nodeID, "lines", len(batch), "err", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	for _, e := range batch {
		h.Broker.Publish(e)
	}
	w.WriteHeader(http.StatusNoContent)
}

// toEntry attributes and sanitises one log line. Values are clamped to the
// column ranges so one odd line cannot fail (and so wedge) a whole batch.
func toEntry(idx NodeRouteIndex, line caddyLogLine) (Entry, bool) {
	// Caddy logs the host as request.host (top-level), not in headers.
	// Fall back to the Host header only for non-Caddy producers.
	host := stripPort(line.Request.Host)
	if host == "" {
		if vals := line.Request.Headers["Host"]; len(vals) > 0 {
			host = stripPort(vals[0])
		}
	}
	if host == "" {
		return Entry{}, false
	}
	// Attribute against the authenticated node's own routes, honouring path
	// routing: several routes may share a domain on different path prefixes.
	routeID, ok := idx.Resolve(host, line.Request.URI)
	if !ok {
		return Entry{}, false
	}
	ts := time.Unix(0, int64(line.TS*1e9))
	if line.TS <= 0 || ts.Year() > 9999 {
		ts = time.Now()
	}
	ua := ""
	if vals := line.Request.Headers["User-Agent"]; len(vals) > 0 {
		ua = vals[0]
	}
	latencyMS := int(min(max(line.Duration*1000, 0), math.MaxInt32))
	// Prefer client_ip (real client after trusted-proxy resolution), then
	// remote_ip, then remote_addr - Caddy emits client_ip/remote_ip, not remote_addr.
	remote := line.Request.ClientIP
	if remote == "" {
		remote = line.Request.RemoteIP
	}
	if remote == "" {
		remote = line.Request.RemoteAddr
	}
	remote = stripPort(remote)
	status := line.Status
	if status < 0 || status > 999 {
		status = 0
	}

	return Entry{
		RouteID:   routeID,
		TS:        ts,
		Method:    truncUTF8(line.Request.Method, 16),
		URI:       truncUTF8(line.Request.URI, 2048),
		Status:    status,
		LatencyMS: latencyMS,
		RemoteIP:  truncUTF8(remote, 45),
		UserAgent: truncUTF8(ua, 512),
		BytesResp: max(line.Size, 0),
		BytesReq:  max(line.BytesRead, 0),
		Proto:     normalizeProto(line.Request.Proto),
		Country:   resolveCountry(line.Request.ClientIP, line.Request.RemoteIP),
		ASNOrg:    resolveASNOrg(line.Request.ClientIP, line.Request.RemoteIP),
	}, true
}

// truncUTF8 cuts s to at most n bytes without leaving a split rune behind
// (MySQL rejects invalid utf8mb4).
func truncUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// normalizeProto maps verbose Caddy proto strings to short tokens for storage.
func normalizeProto(p string) string {
	switch p {
	case "HTTP/1.1":
		return "h1"
	case "HTTP/2.0", "HTTP/2":
		return "h2"
	case "HTTP/3.0", "HTTP/3":
		return "h3"
	default:
		if len(p) > 8 {
			return p[:8]
		}
		return p
	}
}

// resolveASNOrg returns the ASN organization name for the request client IP.
// Falls back to remoteIP when clientIP is empty; returns "" if ASN DB is absent.
func resolveASNOrg(clientIP, remoteIP string) string {
	ip := clientIP
	if ip == "" {
		ip = remoteIP
	}
	if ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	_, org, ok := geoip.LookupASN(parsed)
	if !ok {
		return ""
	}
	if len(org) > 128 {
		org = org[:128]
	}
	return org
}

// resolveCountry returns the ISO-2 country code for the request client IP.
// Falls back to remoteIP when clientIP is empty; returns "" if geoip is unavailable.
func resolveCountry(clientIP, remoteIP string) string {
	ip := clientIP
	if ip == "" {
		ip = remoteIP
	}
	if ip == "" {
		return ""
	}
	code := geoip.Global().LookupISO2(ip)
	// Guard CHAR(2) column; mirrors ua[:512]/uri[:2048] truncation in ingest.
	if len(code) > 2 {
		code = code[:2]
	}
	return code
}

// stripPort removes the :port suffix from host:port strings.
func stripPort(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			// IPv6 [::1]:port
			if i > 0 && addr[0] == '[' {
				return addr[1 : i-1]
			}
			// Disambiguate: if there's no dot in the prefix it might be
			// pure IPv6 without brackets - leave it.
			for j := 0; j < i; j++ {
				if addr[j] == '.' || addr[j] == ']' {
					return addr[:i]
				}
			}
			// Numeric-only prefix = pure port with no host part; skip.
			_, err := strconv.Atoi(addr[:i])
			if err != nil {
				return addr[:i]
			}
			return addr
		}
	}
	return addr
}
