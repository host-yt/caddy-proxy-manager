// Package metrics scrapes Caddy's /metrics endpoint on each enabled node
// and stores aggregate samples in node_traffic_samples.
//
// Caddy must have the `metrics` module configured (we enable it on the
// Admin API listener by default). The endpoint speaks the Prometheus
// text-format; we parse only the counters we care about.
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
)

// Sample is one snapshot of cumulative counters from a node.
type Sample struct {
	NodeID        int64
	RequestsTotal uint64
	ErrorsTotal   uint64 // 5xx + 4xx
	BytesInTotal  uint64
	BytesOutTotal uint64
	ActiveConns   uint32
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
		"DELETE FROM node_traffic_samples WHERE sampled_at < (NOW() - INTERVAL 14 DAY)")
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
// We sum across labels because Caddy exposes per-server/per-code series and
// we only need aggregate per-node values at this layer.
func parse(r io.Reader, nodeID int64) (Sample, error) {
	s := Sample{NodeID: nodeID}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		name, val, ok := splitMetric(line)
		if !ok {
			continue
		}
		switch {
		case startsWith(name, "caddy_http_requests_total"):
			s.RequestsTotal += uint64(val)
		case startsWith(name, "caddy_http_response_size_bytes_sum"):
			s.BytesOutTotal += uint64(val)
		case startsWith(name, "caddy_http_request_size_bytes_sum"):
			s.BytesInTotal += uint64(val)
		case startsWith(name, "caddy_http_requests_in_flight"):
			s.ActiveConns += uint32(val)
		case startsWith(name, "caddy_http_request_errors_total"):
			s.ErrorsTotal += uint64(val)
		}
	}
	return s, sc.Err()
}

// splitMetric parses a single Prometheus line:
//
//	metric_name{labels...} VALUE [TIMESTAMP]
//
// Returns the metric name (no labels) and the numeric value.
func splitMetric(line string) (string, float64, bool) {
	// Find first space → value+ts after it.
	sp := strings.LastIndexByte(line, ' ')
	if sp < 0 {
		return "", 0, false
	}
	rest := strings.TrimSpace(line[sp+1:])
	v, err := strconv.ParseFloat(rest, 64)
	if err != nil {
		return "", 0, false
	}
	head := line[:sp]
	// Strip {labels} if present.
	if i := strings.IndexByte(head, '{'); i > 0 {
		head = head[:i]
	}
	return strings.TrimSpace(head), v, true
}

func startsWith(s, prefix string) bool { return strings.HasPrefix(s, prefix) }
