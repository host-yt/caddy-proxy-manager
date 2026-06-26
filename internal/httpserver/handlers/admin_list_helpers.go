package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/listparams"
)

// likeContains builds a "%term%" LIKE pattern with \ % _ escaped so user
// input is matched literally, not as wildcards. Pair with ESCAPE '\\'.
func likeContains(q string) string {
	q = strings.ReplaceAll(q, `\`, `\\`)
	q = strings.ReplaceAll(q, "%", `\%`)
	q = strings.ReplaceAll(q, "_", `\_`)
	return "%" + q + "%"
}

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
