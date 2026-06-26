package handlers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/listparams"
)

// parseListParams wraps listparams.Parse with project defaults.
func parseListParams(r *http.Request, allowed []string, sortDefault, dirDefault string, sizeDefault int) listparams.Params {
	return listparams.Parse(r, allowed, listparams.Defaults{
		Sort: sortDefault,
		Dir:  dirDefault,
		Size: sizeDefault,
	})
}

// buildPageURL preserves all current query params but overrides page.
func buildPageURL(q url.Values, page int) string {
	return listparams.BuildURL(q, map[string]string{"page": fmt.Sprintf("%d", page)})
}
