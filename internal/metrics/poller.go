// Package metrics scrapes Caddy's /metrics endpoint on each enabled node
// and stores aggregate samples in node_traffic_samples.
//
// Caddy must have the `metrics` module configured (we enable it on the
// Admin API listener by default). The endpoint speaks the Prometheus
// text-format; we parse only the counters we care about.
//
// Per-host granularity: Caddy's built-in caddy_http_requests_total uses
// {server, handler, code, method} labels - no host/SNI label per vhost.
// When Caddy exposes a "server_name" label (custom builds or future versions),
// parse() extracts it into HostSamples for per-domain accounting.
package metrics

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// HostSample holds per-domain request/error counters extracted from Caddy labels.
type HostSample struct {
	RequestsTotal uint64
	ErrorsTotal   uint64
}

// Sample is one snapshot of cumulative counters from a node.
type Sample struct {
	NodeID        int64
	RequestsTotal uint64
	ErrorsTotal   uint64 // 5xx + 4xx
	BytesInTotal  uint64
	BytesOutTotal uint64
	ActiveConns   uint32
	// HostSamples aggregates per-domain request/error counts when Caddy
	// exposes a "server_name" label. Empty on stock Caddy (all vhosts share
	// the srv0 server label without a per-host breakdown).
	HostSamples map[string]*HostSample
}

// Poller polls every enabled node every Interval and writes a Sample.
type Poller struct {
	DB       func() *sql.DB
	Logger   *slog.Logger
	Interval time.Duration
	HC       *http.Client
}

// New returns a Poller with sane defaults. Use Run to start.
func New(db func() *sql.DB, logger *slog.Logger) *Poller {
	return &Poller{
		DB:       db,
		Logger:   logger,
		Interval: 60 * time.Second,
		HC:       &http.Client{Timeout: 5 * time.Second},
	}
}

// Run blocks until ctx is done. Spawned from main as a goroutine.
func (p *Poller) Run(ctx context.Context) {
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	// Warm up so the first sample lands quickly.
	p.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.tick(ctx)
		}
	}
}

func (p *Poller) tick(ctx context.Context) {
	db := p.DB()
	if db == nil {
		return
	}
	type node struct {
		id  int64
		url string
	}
	rows, err := db.QueryContext(ctx,
		"SELECT id, api_url FROM caddy_nodes WHERE is_enabled = 1")
	if err != nil {
		p.Logger.Warn("metrics: list nodes", "err", err)
		return
	}
	var nodes []node
	for rows.Next() {
		var n node
		if err := rows.Scan(&n.id, &n.url); err == nil {
			nodes = append(nodes, n)
		}
	}
	rows.Close()

	for _, n := range nodes {
		s, err := p.scrape(ctx, n.id, n.url)
		if err != nil {
			p.Logger.Debug("metrics scrape failed", "node_id", n.id, "err", err)
			continue
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO node_traffic_samples
			   (node_id, requests_total, errors_total, bytes_in_total, bytes_out_total, active_conns)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			s.NodeID, s.RequestsTotal, s.ErrorsTotal, s.BytesInTotal, s.BytesOutTotal, s.ActiveConns,
		); err != nil {
			p.Logger.Warn("metrics: insert sample", "node_id", n.id, "err", err)
		}
	}

	// Prune: keep 14 days of samples (≈20k rows per node at 60s interval).
	_, _ = db.ExecContext(ctx,
		"DELETE FROM node_traffic_samples WHERE sampled_at < ("+store.DateSub(14, "DAY")+")")
}

func (p *Poller) scrape(ctx context.Context, nodeID int64, apiURL string) (Sample, error) {
	url := strings.TrimRight(apiURL, "/") + "/metrics"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Sample{}, err
	}
	resp, err := p.HC.Do(req)
	if err != nil {
		return Sample{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Sample{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	return parse(resp.Body, nodeID)
}

// parse reads Prometheus text format and extracts Caddy counters we care about.
//
// Node-level aggregates are always accumulated. When a "server_name" label is
// present (custom Caddy builds or future versions), per-host counters are also
// collected into Sample.HostSamples keyed by domain name.
func parse(r io.Reader, nodeID int64) (Sample, error) {
	s := Sample{NodeID: nodeID, HostSamples: make(map[string]*HostSample)}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		name, labels, val, ok := splitMetric(line)
		if !ok {
			continue
		}
		switch {
		case startsWith(name, "caddy_http_requests_total"):
			s.RequestsTotal += uint64(val)
			if h := labels["server_name"]; h != "" {
				hostSample(s.HostSamples, h).RequestsTotal += uint64(val)
			}
		case startsWith(name, "caddy_http_response_size_bytes_sum"):
			s.BytesOutTotal += uint64(val)
		case startsWith(name, "caddy_http_request_size_bytes_sum"):
			s.BytesInTotal += uint64(val)
		case startsWith(name, "caddy_http_requests_in_flight"):
			s.ActiveConns += uint32(val)
		case startsWith(name, "caddy_http_request_errors_total"):
			s.ErrorsTotal += uint64(val)
			if h := labels["server_name"]; h != "" {
				hostSample(s.HostSamples, h).ErrorsTotal += uint64(val)
			}
		}
	}
	return s, sc.Err()
}

// hostSample returns the HostSample for a domain, creating it on first access.
func hostSample(m map[string]*HostSample, host string) *HostSample {
	if hs, ok := m[host]; ok {
		return hs
	}
	hs := &HostSample{}
	m[host] = hs
	return hs
}

// splitMetric parses a single Prometheus line:
//
//	metric_name{labels...} VALUE [TIMESTAMP]
//
// Returns the metric name, a map of label key→value pairs, and the numeric value.
func splitMetric(line string) (string, map[string]string, float64, bool) {
	// Last space separates value (+ optional timestamp) from the metric identity.
	sp := strings.LastIndexByte(line, ' ')
	if sp < 0 {
		return "", nil, 0, false
	}
	rest := strings.TrimSpace(line[sp+1:])
	v, err := strconv.ParseFloat(rest, 64)
	if err != nil {
		return "", nil, 0, false
	}
	head := line[:sp]

	var labelStr string
	name := head
	if i := strings.IndexByte(head, '{'); i > 0 {
		name = head[:i]
		if j := strings.LastIndexByte(head, '}'); j > i {
			labelStr = head[i+1 : j]
		}
	}
	return strings.TrimSpace(name), parseLabels(labelStr), v, true
}

// parseLabels decodes a Prometheus label string (k="v",k2="v2") into a map.
// Values may contain escaped quotes; we do a best-effort linear scan.
func parseLabels(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := make(map[string]string)
	for s != "" {
		// key
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(s[:eq])
		s = s[eq+1:]
		// quoted value
		if len(s) == 0 || s[0] != '"' {
			break
		}
		s = s[1:]
		var val strings.Builder
		for len(s) > 0 {
			if s[0] == '\\' && len(s) > 1 {
				val.WriteByte(s[1])
				s = s[2:]
				continue
			}
			if s[0] == '"' {
				s = s[1:]
				break
			}
			val.WriteByte(s[0])
			s = s[1:]
		}
		out[key] = val.String()
		// skip comma separator
		if len(s) > 0 && s[0] == ',' {
			s = s[1:]
		}
	}
	return out
}

func startsWith(s, prefix string) bool { return strings.HasPrefix(s, prefix) }
