package accesslog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
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
}

type caddyLogReq struct {
	Method     string              `json:"method"`
	URI        string              `json:"uri"`
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
	// RouteByDomain resolves a domain → route_id.
	RouteByDomain func(ctx context.Context, domain string) (int64, bool)
	// AuthNode validates a node agent token (Bearer). The /internal/access-log
	// route is reachable on the public app port, so every POST must carry a
	// valid per-node token or it is rejected. Required; if nil all calls 401.
	AuthNode func(ctx context.Context, token string) bool
}

func (h *IngestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Authenticate the node agent. The endpoint is publicly reachable, so an
	// unauthenticated caller must not be able to inject/poison host logs.
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" || h.AuthNode == nil || !h.AuthNode(ctx, token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxIngestBody)
	// Scan line-by-line: each NDJSON line is decoded independently so a single
	// malformed/truncated line is skipped, not the rest of the batch (a shared
	// json.Decoder loses position on a syntax error and would drop everything
	// after it). Non-access log lines (no Host) are ignored downstream.
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // tolerate long log lines (1 MiB cap)
	for sc.Scan() {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var line caddyLogLine
		if err := json.Unmarshal(b, &line); err != nil {
			continue // skip malformed line, keep ingesting the rest
		}
		h.ingest(ctx, line)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *IngestHandler) ingest(ctx context.Context, line caddyLogLine) {
	// Resolve host from the recorded request headers.
	host := ""
	if vals := line.Request.Headers["Host"]; len(vals) > 0 {
		host = stripPort(vals[0])
	}
	if host == "" {
		return
	}
	routeID, ok := h.RouteByDomain(ctx, host)
	if !ok {
		return
	}
	ts := time.Unix(0, int64(line.TS*1e9))
	ua := ""
	if vals := line.Request.Headers["User-Agent"]; len(vals) > 0 {
		ua = vals[0]
	}
	if len(ua) > 512 {
		ua = ua[:512]
	}
	uri := line.Request.URI
	if len(uri) > 2048 {
		uri = uri[:2048]
	}
	latencyMS := int(line.Duration * 1000)
	remote := stripPort(line.Request.RemoteAddr)

	e := Entry{
		RouteID:   routeID,
		TS:        ts,
		Method:    line.Request.Method,
		URI:       uri,
		Status:    line.Status,
		LatencyMS: latencyMS,
		RemoteIP:  remote,
		UserAgent: ua,
	}
	if err := h.Store.Insert(ctx, e); err != nil {
		h.Logger.Warn("accesslog insert", "err", err)
		return
	}
	h.Broker.Publish(e)
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
