package handlers

import (
	"context"
	"html/template"
	"net/http"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// clientWorldmapData drives the client-facing traffic-by-country map. Scoped to
// the logged-in client's own routes only - never another client's traffic.
type clientWorldmapData struct {
	baseAppData
	Countries      []*trafficCountryEntry
	CountryJSON    template.JS
	MaxCount       int64
	TotalRequests  int64
	UnknownCount   int64
	UnknownPercent float64
	Hosts          []trafficHostOption
	SelectedRoute  int64
	SelectedHost   string
	Range          string
	GeoIPAvailable bool
	DBUnavailable  bool
	WorldSVG       template.HTML // inlined SVG; object-src 'none' blocks <object>
}

// ClientWorldMap renders visitor traffic by country for the client's own hosts.
func (h *ClientHandlers) ClientWorldMap(w http.ResponseWriter, r *http.Request) {
	d := clientWorldmapData{baseAppData: h.base(r, "Traffic by country")}
	d.WorldSVG = loadWorldSVG()

	db := h.DB()
	sess := middleware.SessionFromContext(r.Context())
	if db == nil || sess == nil {
		d.DBUnavailable = db == nil
		h.render(w, "worldmap", d)
		return
	}

	resolver := geoip.Global()
	d.GeoIPAvailable = resolver.Available()

	dur, rangeKey := parseTrafficRange(r)
	d.Range = rangeKey

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	clientID, err := clientIDFor(ctx, db, sess.UserID)
	if err != nil {
		// No client record: render an empty (but scoped) view.
		h.render(w, "worldmap", d)
		return
	}

	// Scope every query to this single client's routes.
	scope := []int64{clientID}
	d.Hosts = loadTrafficHosts(ctx, db, scope, false)

	if rid := parseRouteID(r); rid > 0 && hostInOptions(d.Hosts, rid) {
		d.SelectedRoute = rid
		d.SelectedHost = hostLabel(d.Hosts, rid)
	}

	conds, args := worldmapWhere(dur, d.SelectedRoute, scope, false)
	agg := aggregateTrafficByCountry(ctx, db, conds, args, resolver)
	if agg.dbErr != nil {
		h.Logger.Warn("client worldmap aggregate", "err", agg.dbErr)
	}

	d.TotalRequests = agg.total
	d.UnknownCount = agg.unknown
	if agg.total > 0 {
		d.UnknownPercent = float64(agg.unknown) / float64(agg.total) * 100
	}
	d.MaxCount, d.Countries = rankTrafficCountries(agg)
	d.CountryJSON = template.JS(buildTrafficJSON(agg.byCountry))

	h.render(w, "worldmap", d)
}
