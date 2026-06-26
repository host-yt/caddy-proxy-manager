// Package listparams parses and validates standard list-view query params.
// It protects ORDER BY from injection by whitelisting sortable columns.
package listparams

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	defaultSize = 50
	maxSize     = 500
)

// Params holds the parsed, validated list parameters from a request.
type Params struct {
	Page int    // 1-based
	Size int    // clamped to [1, maxSize]
	Sort string // validated column name, empty means default
	Dir  string // "asc" or "desc"
	Q    string // free-text search term
}

// Offset returns the SQL OFFSET value for the current page.
func (p *Params) Offset() int { return (p.Page - 1) * p.Size }

// OrderBySQL returns a safe ORDER BY fragment, e.g. "created_at DESC".
// Falls back to fallback if Sort is empty.
func (p *Params) OrderBySQL(fallback string) string {
	col := p.Sort
	if col == "" {
		col = fallback
	}
	return col + " " + strings.ToUpper(p.Dir)
}

// ParseURL parses list params from query string. allowed is the set of
// permitted sort column names; any Sort value not in the set is rejected
// (set to ""). The caller must supply defaults for sort+dir via Defaults.
func ParseURL(q url.Values, allowed []string, defaults Defaults) Params {
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(q.Get("size"))
	if size < 1 {
		size = defaults.Size
	}
	if size < 1 {
		size = defaultSize
	}
	if size > maxSize {
		size = maxSize
	}

	sort := strings.TrimSpace(q.Get("sort"))
	if !isAllowed(sort, allowed) {
		sort = defaults.Sort
	}

	dir := strings.ToLower(strings.TrimSpace(q.Get("dir")))
	if dir != "asc" && dir != "desc" {
		dir = defaults.Dir
	}
	if dir == "" {
		dir = "desc"
	}

	return Params{
		Page: page,
		Size: size,
		Sort: sort,
		Dir:  dir,
		Q:    strings.TrimSpace(q.Get("q")),
	}
}

// Parse is a convenience wrapper over ParseURL using the request's URL.
func Parse(r *http.Request, allowed []string, defaults Defaults) Params {
	return ParseURL(r.URL.Query(), allowed, defaults)
}

// Defaults are the fallback values when params are absent or invalid.
type Defaults struct {
	Sort string
	Dir  string // "asc" or "desc"
	Size int
}

// PageInfo carries pagination metadata for the template.
type PageInfo struct {
	Page     int
	Size     int
	Total    int
	TotalPgs int
	HasPrev  bool
	HasNext  bool
	PrevPage int
	NextPage int
}

// NewPageInfo builds page metadata from current params + total row count.
func NewPageInfo(p Params, total int) PageInfo {
	totalPgs := (total + p.Size - 1) / p.Size
	if totalPgs < 1 {
		totalPgs = 1
	}
	return PageInfo{
		Page:     p.Page,
		Size:     p.Size,
		Total:    total,
		TotalPgs: totalPgs,
		HasPrev:  p.Page > 1,
		HasNext:  p.Page < totalPgs,
		PrevPage: p.Page - 1,
		NextPage: p.Page + 1,
	}
}

// BuildURL constructs a query string preserving existing params while
// overriding specific keys. Useful for next/prev page links in templates.
func BuildURL(base url.Values, overrides map[string]string) string {
	q := url.Values{}
	for k, vs := range base {
		q[k] = vs
	}
	for k, v := range overrides {
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
	}
	return "?" + q.Encode()
}

// SortURL returns a URL that sorts by col, toggling dir if already active.
func SortURL(base url.Values, col, currentSort, currentDir string) string {
	dir := "asc"
	if col == currentSort && currentDir == "asc" {
		dir = "desc"
	}
	return BuildURL(base, map[string]string{"sort": col, "dir": dir, "page": "1"})
}

// SortIcon returns an arrow indicator for column headers in templates.
func SortIcon(col, currentSort, currentDir string) string {
	if col != currentSort {
		return ""
	}
	if currentDir == "asc" {
		return "asc"
	}
	return "desc"
}

// CountSQL wraps a base query with COUNT(*). The caller supplies a WHERE
// clause string (may be "1=1") and args for the base table.
// Returns "SELECT COUNT(*) FROM (" + base + ") AS _c" ready for QueryRowContext.
func CountSQL(baseFromWhere string) string {
	return fmt.Sprintf("SELECT COUNT(*) FROM (%s) AS _lp_count", baseFromWhere)
}

func isAllowed(col string, allowed []string) bool {
	if col == "" {
		return false
	}
	for _, a := range allowed {
		if a == col {
			return true
		}
	}
	return false
}
