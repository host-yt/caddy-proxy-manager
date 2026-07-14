package dnssteer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const cfAPIBase = "https://api.cloudflare.com/client/v4"

// cloudflareProvider talks to the Cloudflare v4 REST API directly with
// net/http (same approach as internal/cloudflare's token-verify call) -
// no SDK dependency needed for the handful of calls DNS steering makes.
type cloudflareProvider struct {
	token string
	hc    *http.Client
}

func newCloudflareProvider(fields map[string]string) (*cloudflareProvider, error) {
	token := fields["api_token"]
	if token == "" {
		return nil, errors.New("dnssteer: cloudflare api_token missing")
	}
	return &cloudflareProvider{token: token, hc: &http.Client{Timeout: 8 * time.Second}}, nil
}

type cfAPIError struct {
	Message string `json:"message"`
}

func cfErr(errs []cfAPIError) error {
	if len(errs) == 0 {
		return errors.New("cloudflare: request failed")
	}
	return fmt.Errorf("cloudflare: %s", errs[0].Message)
}

// do issues one Cloudflare API call and decodes the JSON body into out.
// Errors surface via the body's success/errors fields, not HTTP status -
// Cloudflare returns a parseable JSON error body on 4xx too.
func (p *cloudflareProvider) do(ctx context.Context, method, path string, body any, out any) error {
	var reqBody io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, cfAPIBase+path, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("cloudflare: decode response: %w", err)
	}
	return nil
}

// zoneID resolves the apex zone name (dns_providers.name) to Cloudflare's
// internal zone ID, required by every dns_records call.
func (p *cloudflareProvider) zoneID(ctx context.Context, zone string) (string, error) {
	var out struct {
		Success bool `json:"success"`
		Result  []struct {
			ID string `json:"id"`
		} `json:"result"`
		Errors []cfAPIError `json:"errors"`
	}
	q := url.Values{"name": {zone}}
	if err := p.do(ctx, http.MethodGet, "/zones?"+q.Encode(), nil, &out); err != nil {
		return "", err
	}
	if !out.Success || len(out.Result) == 0 {
		if len(out.Errors) > 0 {
			return "", cfErr(out.Errors)
		}
		return "", fmt.Errorf("cloudflare: zone %q not found", zone)
	}
	return out.Result[0].ID, nil
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// GetRecords returns every A/AAAA record in the zone; the caller (Reconciler)
// filters by record name and diffs against desired node IPs.
func (p *cloudflareProvider) GetRecords(ctx context.Context, zone string) ([]Record, error) {
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out struct {
		Success bool         `json:"success"`
		Result  []cfRecord   `json:"result"`
		Errors  []cfAPIError `json:"errors"`
	}
	// per_page=5000 is Cloudflare's max; steered zones are small so one page suffices.
	if err := p.do(ctx, http.MethodGet, "/zones/"+zid+"/dns_records?per_page=5000", nil, &out); err != nil {
		return nil, err
	}
	if !out.Success {
		return nil, cfErr(out.Errors)
	}
	recs := make([]Record, 0, len(out.Result))
	for _, r := range out.Result {
		if r.Type != "A" && r.Type != "AAAA" {
			continue
		}
		recs = append(recs, Record{ID: r.ID, Type: r.Type, Name: r.Name, Value: r.Content, TTL: time.Duration(r.TTL) * time.Second})
	}
	return recs, nil
}

type cfCreateReq struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
}

// AppendRecords creates one record per entry (Cloudflare has no bulk-create).
func (p *cloudflareProvider) AppendRecords(ctx context.Context, zone string, recs []Record) ([]Record, error) {
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(recs))
	for _, rec := range recs {
		ttl := 1 // Cloudflare "automatic"
		if rec.TTL > 0 {
			ttl = int(rec.TTL.Seconds())
			if ttl < 60 {
				ttl = 60 // Cloudflare's floor for non-proxied records
			}
		}
		var resp struct {
			Success bool         `json:"success"`
			Result  cfRecord     `json:"result"`
			Errors  []cfAPIError `json:"errors"`
		}
		body := cfCreateReq{Type: rec.Type, Name: rec.Name, Content: rec.Value, TTL: ttl}
		if err := p.do(ctx, http.MethodPost, "/zones/"+zid+"/dns_records", body, &resp); err != nil {
			return out, err
		}
		if !resp.Success {
			return out, cfErr(resp.Errors)
		}
		out = append(out, Record{ID: resp.Result.ID, Type: resp.Result.Type, Name: resp.Result.Name, Value: resp.Result.Content, TTL: time.Duration(resp.Result.TTL) * time.Second})
	}
	return out, nil
}

// DeleteRecords removes records by their provider-assigned ID (populated by
// a prior GetRecords call); a Record without an ID can't be targeted.
func (p *cloudflareProvider) DeleteRecords(ctx context.Context, zone string, recs []Record) ([]Record, error) {
	zid, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(recs))
	for _, rec := range recs {
		if rec.ID == "" {
			return out, fmt.Errorf("cloudflare: delete requires a record ID (value=%s)", rec.Value)
		}
		var resp struct {
			Success bool         `json:"success"`
			Errors  []cfAPIError `json:"errors"`
		}
		if err := p.do(ctx, http.MethodDelete, "/zones/"+zid+"/dns_records/"+rec.ID, nil, &resp); err != nil {
			return out, err
		}
		if !resp.Success {
			return out, cfErr(resp.Errors)
		}
		out = append(out, rec)
	}
	return out, nil
}
