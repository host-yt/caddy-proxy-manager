package handlers

import (
	"context"
	"html/template"
	"net/http"
	"sort"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
)

// ClientWorldMap renders the world map for regular (client-role) users.
// Clients see all node countries read-only - no client data exposed.
func (h *ClientHandlers) ClientWorldMap(w http.ResponseWriter, r *http.Request) {
	d := clientWorldmapData{baseAppData: h.base(r, "Node world map")}
	d.WorldSVG = loadWorldSVG()

	db := h.DB()
	if db == nil {
		d.DBUnavailable = true
		h.render(w, "worldmap", d)
		return
	}

	resolver := geoip.Global()
	d.GeoIPAvailable = resolver.Available()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	nodes := loadWorldmapNodes(ctx, db)
	byCountry := map[string]*worldmapCountryEntry{}

	for _, n := range nodes {
		code := resolver.LookupISO2(n.PublicIP)
		if code == "" {
			d.Unknown = append(d.Unknown, n)
			continue
		}
		e := byCountry[code]
		if e == nil {
			e = &worldmapCountryEntry{
				Code: code,
				Name: iso2Name(code),
			}
			byCountry[code] = e
		}
		e.Nodes = append(e.Nodes, *n)
		e.NodeCount++
	}

	for _, e := range byCountry {
		statuses := make([]string, 0, len(e.Nodes))
		for _, n := range e.Nodes {
			statuses = append(statuses, n.HealthStatus)
		}
		e.Health = worldmapNodeHealth(statuses)
		d.Countries = append(d.Countries, e)
	}
	sort.Slice(d.Countries, func(i, j int) bool {
		return d.Countries[i].Name < d.Countries[j].Name
	})

	d.CountryJSON = buildCountryJSON(d.Countries)

	h.render(w, "worldmap", d)
}

type clientWorldmapData struct {
	baseAppData
	Countries      []*worldmapCountryEntry
	CountryJSON    string
	Unknown        []*worldmapNodeEntry
	GeoIPAvailable bool
	DBUnavailable  bool
	WorldSVG       template.HTML // inlined SVG; object-src 'none' blocks <object>
}
