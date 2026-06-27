package handlers

import (
	"context"
	"database/sql"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// worldmapDistinctIPCap bounds how many distinct visitor IPs we resolve per
// page load. host_access_log keeps only ~500 rows/route, but the GROUP BY can
// still surface many IPs system-wide; cap so geoip lookups stay cheap.
const worldmapDistinctIPCap = 5000

// trafficRanges enumerates the supported `range` query values, newest first.
var trafficRanges = []struct {
	Key   string
	Label string
	Dur   time.Duration
}{
	{"24h", "Last 24 hours", 24 * time.Hour},
	{"7d", "Last 7 days", 7 * 24 * time.Hour},
	{"30d", "Last 30 days", 30 * 24 * time.Hour},
}

// parseTrafficRange returns the window duration and canonical key for a `range`
// query param, defaulting to 7d when missing or invalid.
func parseTrafficRange(r *http.Request) (time.Duration, string) {
	want := r.URL.Query().Get("range")
	for _, tr := range trafficRanges {
		if tr.Key == want {
			return tr.Dur, tr.Key
		}
	}
	return 7 * 24 * time.Hour, "7d"
}

// trafficCountryEntry is one country's request volume for the ranked table.
type trafficCountryEntry struct {
	Code       string // ISO alpha-2 upper, e.g. "DE"
	Name       string // human-readable country name
	Count      int64
	Percent    float64 // share of grand total (0..100)
	BarPercent float64 // share of the busiest country (0..100), for bar width
}

// trafficHostOption is one selectable host for the per-host dropdown.
type trafficHostOption struct {
	RouteID int64
	Label   string // "domain" or "domain/path"
}

// worldmapData drives the admin traffic-by-country map.
type worldmapData struct {
	baseAdminData
	Countries      []*trafficCountryEntry // countries with traffic, sorted by count desc
	CountryJSON    string                 // {"DE":1234} for JS heatmap coloring
	MaxCount       int64                  // largest single-country count, for bar scaling
	TotalRequests  int64                  // grand total across all resolved + unknown
	UnknownCount   int64                  // requests from private/unresolvable IPs
	UnknownPercent float64                // unknown share of total (0..100)
	Hosts          []trafficHostOption    // dropdown options ("All hosts" is implicit)
	SelectedRoute  int64                  // 0 = all hosts
	SelectedHost   string                 // label of the selected host, "" = all
	Range          string                 // canonical range key (24h|7d|30d)
	GeoIPAvailable bool
	DBUnavailable  bool
	WorldSVG       template.HTML // inlined world SVG; CSP blocks object-src so we inline
}

// AdminWorldMap renders the traffic-by-country map for the whole system, with an
// optional per-host drilldown. Scoped admins only see their assigned clients.
func (h *AdminHandlers) AdminWorldMap(w http.ResponseWriter, r *http.Request) {
	d := worldmapData{baseAdminData: h.base(r, "Traffic by country")}
	d.PageDesc = "Where requests entering the system come from, by visitor country."
	d.WorldSVG = loadWorldSVG()

	var db *sql.DB
	if h.DB != nil {
		db = h.DB()
	}
	if db == nil {
		d.DBUnavailable = true
		h.render(w, "worldmap", d)
		return
	}

	resolver := geoip.Global()
	d.GeoIPAvailable = resolver.Available()

	dur, rangeKey := parseTrafficRange(r)
	d.Range = rangeKey

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	// Resolve admin scope: super_admin sees all clients, others only assigned ones.
	sess := middleware.SessionFromContext(ctx)
	clientIDs, all := []int64(nil), true
	if sess != nil && sess.Role != "super_admin" && h.AdminScope != nil {
		ids, isAll, err := h.AdminScope.ScopeFilter(ctx, sess.UserID)
		if err != nil {
			h.Logger.Warn("worldmap scope", "user_id", sess.UserID, "err", err)
			ids, isAll = nil, false
		}
		clientIDs, all = ids, isAll
	}

	d.Hosts = loadTrafficHosts(ctx, db, clientIDs, all)

	// Per-host filter; honour scope so a scoped admin cannot pin a foreign route.
	if rid := parseRouteID(r); rid > 0 {
		if hostInOptions(d.Hosts, rid) {
			d.SelectedRoute = rid
			d.SelectedHost = hostLabel(d.Hosts, rid)
		}
	}

	conds, args := worldmapWhere(dur, d.SelectedRoute, clientIDs, all)
	agg := aggregateTrafficByCountry(ctx, db, conds, args, resolver)
	if agg.dbErr != nil {
		h.Logger.Warn("worldmap aggregate", "err", agg.dbErr)
	}
	fillWorldmapData(&d, agg)

	h.render(w, "worldmap", d)
}

// parseRouteID reads the route_id query param, 0 when absent/invalid.
func parseRouteID(r *http.Request) int64 {
	v, _ := strconv.ParseInt(r.URL.Query().Get("route_id"), 10, 64)
	if v < 0 {
		return 0
	}
	return v
}

// trafficAgg is the raw result of a per-country aggregation pass.
type trafficAgg struct {
	byCountry map[string]int64
	total     int64
	unknown   int64
	dbErr     error
}

// worldmapWhere builds the WHERE conditions + args for the aggregation query.
// dur sets the time window; routeID>0 filters one host; a non-"all" scope
// restricts to the given client IDs via the routes->services join.
// Blank remote_ip rows are dropped so the GROUP BY stays lean.
func worldmapWhere(dur time.Duration, routeID int64, clientIDs []int64, all bool) (string, []any) {
	var conds []string
	var args []any
	conds = append(conds, "hal.ts >= ?")
	args = append(args, time.Now().UTC().Add(-dur))
	conds = append(conds, "hal.remote_ip <> ''")
	if routeID > 0 {
		conds = append(conds, "hal.route_id = ?")
		args = append(args, routeID)
	}
	if !all {
		// Scoped admin / client with no visible routes: force an empty result
		// rather than leaking system-wide traffic.
		if len(clientIDs) == 0 {
			conds = append(conds, "1 = 0")
		} else {
			conds = append(conds, "hal.route_id IN (SELECT r.id FROM routes r JOIN services s ON s.id = r.service_id WHERE s.client_id IN ("+placeholders(len(clientIDs))+"))")
			for _, id := range clientIDs {
				args = append(args, id)
			}
		}
	}
	return strings.Join(conds, " AND "), args
}

// aggregateTrafficByCountry sums request counts per country. We GROUP BY
// remote_ip in SQL so each distinct visitor IP is resolved through geoip
// exactly once (cached), not once per row. Distinct IPs are capped to bound
// geoip cost; the tail beyond the cap is folded into the unknown bucket.
func aggregateTrafficByCountry(ctx context.Context, db *sql.DB, conds string, args []any, resolver *geoip.Resolver) trafficAgg {
	out := trafficAgg{byCountry: map[string]int64{}}
	q := `SELECT hal.remote_ip, COUNT(*) AS c
	      FROM host_access_log hal
	      WHERE ` + conds + `
	      GROUP BY hal.remote_ip
	      ORDER BY c DESC
	      LIMIT ?`
	args = append(append([]any(nil), args...), worldmapDistinctIPCap+1)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		out.dbErr = err
		return out
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var ip string
		var cnt int64
		if err := rows.Scan(&ip, &cnt); err != nil {
			continue
		}
		seen++
		out.total += cnt
		// Past the cap: count toward total+unknown but skip the geoip lookup.
		if seen > worldmapDistinctIPCap {
			out.unknown += cnt
			continue
		}
		code := resolver.LookupISO2(ip)
		if code == "" {
			out.unknown += cnt
			continue
		}
		out.byCountry[code] += cnt
	}
	out.dbErr = rows.Err()
	return out
}

// fillWorldmapData populates the ranked table, JSON blob, totals, and max from
// an aggregation result.
func fillWorldmapData(d *worldmapData, agg trafficAgg) {
	d.TotalRequests = agg.total
	d.UnknownCount = agg.unknown
	if agg.total > 0 {
		d.UnknownPercent = float64(agg.unknown) / float64(agg.total) * 100
	}
	d.MaxCount, d.Countries = rankTrafficCountries(agg)
	d.CountryJSON = buildTrafficJSON(agg.byCountry)
}

// rankTrafficCountries turns a country->count map into a slice sorted by count
// desc (then name), with per-country percent of total. Returns the max count
// too, used for bar scaling. Shared by the admin and client handlers.
func rankTrafficCountries(agg trafficAgg) (int64, []*trafficCountryEntry) {
	var max int64
	out := make([]*trafficCountryEntry, 0, len(agg.byCountry))
	for code, cnt := range agg.byCountry {
		if cnt > max {
			max = cnt
		}
		e := &trafficCountryEntry{Code: code, Name: iso2Name(code), Count: cnt}
		if agg.total > 0 {
			e.Percent = float64(cnt) / float64(agg.total) * 100
		}
		out = append(out, e)
	}
	if max > 0 {
		for _, e := range out {
			e.BarPercent = float64(e.Count) / float64(max) * 100
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return max, out
}

// loadTrafficHosts builds the per-host dropdown. all=true returns every route;
// otherwise only routes owned by the given client IDs. Empty scope -> no hosts.
func loadTrafficHosts(ctx context.Context, db *sql.DB, clientIDs []int64, all bool) []trafficHostOption {
	var (
		q    string
		args []any
	)
	if all {
		q = `SELECT r.id, r.domain, COALESCE(r.path_prefix,'') FROM routes r ORDER BY r.domain, r.path_prefix LIMIT 2000`
	} else {
		if len(clientIDs) == 0 {
			return nil
		}
		q = `SELECT r.id, r.domain, COALESCE(r.path_prefix,'')
		     FROM routes r JOIN services s ON s.id = r.service_id
		     WHERE s.client_id IN (` + placeholders(len(clientIDs)) + `)
		     ORDER BY r.domain, r.path_prefix LIMIT 2000`
		for _, id := range clientIDs {
			args = append(args, id)
		}
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []trafficHostOption
	for rows.Next() {
		var id int64
		var domain, path string
		if err := rows.Scan(&id, &domain, &path); err != nil {
			continue
		}
		out = append(out, trafficHostOption{RouteID: id, Label: hostOptionLabel(domain, path)})
	}
	return out
}

func hostOptionLabel(domain, path string) string {
	if path != "" && path != "/" {
		return domain + path
	}
	return domain
}

func hostInOptions(opts []trafficHostOption, id int64) bool {
	for _, o := range opts {
		if o.RouteID == id {
			return true
		}
	}
	return false
}

func hostLabel(opts []trafficHostOption, id int64) string {
	for _, o := range opts {
		if o.RouteID == id {
			return o.Label
		}
	}
	return ""
}

// placeholders returns "?,?,?" for n>0; "?" never appears alone via this when n=0.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// buildTrafficJSON emits {"DE":1234,"US":5678} without an encoding/json import.
// Keys are ISO2 (already validated as 2 letters); values are plain integers.
func buildTrafficJSON(byCountry map[string]int64) string {
	codes := make([]string, 0, len(byCountry))
	for c := range byCountry {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, c := range codes {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		sb.WriteString(c)
		sb.WriteString(`":`)
		sb.WriteString(strconv.FormatInt(byCountry[c], 10))
	}
	sb.WriteByte('}')
	return sb.String()
}

// iso2Name returns a human-readable country name for an ISO alpha-2 code.
// Only the subset relevant to known hosting regions; falls back to the code.
func iso2Name(code string) string {
	if name, ok := iso2Names[code]; ok {
		return name
	}
	return code
}

// iso2Names is a static lookup table for display names.
var iso2Names = map[string]string{
	"AE": "UAE", "AF": "Afghanistan", "AL": "Albania", "AM": "Armenia",
	"AO": "Angola", "AR": "Argentina", "AT": "Austria", "AU": "Australia",
	"AZ": "Azerbaijan", "BA": "Bosnia", "BD": "Bangladesh", "BE": "Belgium",
	"BF": "Burkina Faso", "BG": "Bulgaria", "BI": "Burundi", "BJ": "Benin",
	"BN": "Brunei", "BO": "Bolivia", "BR": "Brazil", "BT": "Bhutan",
	"BW": "Botswana", "BY": "Belarus", "BZ": "Belize", "CA": "Canada",
	"CD": "DR Congo", "CF": "CAR", "CG": "Congo", "CH": "Switzerland",
	"CI": "Ivory Coast", "CL": "Chile", "CM": "Cameroon", "CN": "China",
	"CO": "Colombia", "CR": "Costa Rica", "CU": "Cuba", "CY": "Cyprus",
	"CZ": "Czech Republic", "DE": "Germany", "DJ": "Djibouti", "DK": "Denmark",
	"DO": "Dominican Rep.", "DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia",
	"EG": "Egypt", "EH": "W. Sahara", "ER": "Eritrea", "ES": "Spain",
	"ET": "Ethiopia", "FI": "Finland", "FJ": "Fiji", "FR": "France",
	"GA": "Gabon", "GB": "United Kingdom", "GE": "Georgia", "GH": "Ghana",
	"GL": "Greenland", "GN": "Guinea", "GQ": "Eq. Guinea", "GR": "Greece",
	"GT": "Guatemala", "GW": "Guinea-Bissau", "GY": "Guyana", "HN": "Honduras",
	"HR": "Croatia", "HT": "Haiti", "HU": "Hungary", "ID": "Indonesia",
	"IE": "Ireland", "IL": "Israel", "IN": "India", "IQ": "Iraq",
	"IR": "Iran", "IS": "Iceland", "IT": "Italy", "JO": "Jordan",
	"JP": "Japan", "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia",
	"KP": "North Korea", "KR": "South Korea", "KW": "Kuwait", "KZ": "Kazakhstan",
	"LA": "Laos", "LB": "Lebanon", "LK": "Sri Lanka", "LR": "Liberia",
	"LS": "Lesotho", "LT": "Lithuania", "LV": "Latvia", "LY": "Libya",
	"MA": "Morocco", "MD": "Moldova", "ME": "Montenegro", "MG": "Madagascar",
	"MK": "North Macedonia", "ML": "Mali", "MM": "Myanmar", "MN": "Mongolia",
	"MR": "Mauritania", "MW": "Malawi", "MX": "Mexico", "MY": "Malaysia",
	"MZ": "Mozambique", "NA": "Namibia", "NC": "New Caledonia", "NE": "Niger",
	"NG": "Nigeria", "NI": "Nicaragua", "NL": "Netherlands", "NO": "Norway",
	"NP": "Nepal", "NZ": "New Zealand", "OM": "Oman", "PA": "Panama",
	"PE": "Peru", "PG": "Papua New Guinea", "PH": "Philippines", "PK": "Pakistan",
	"PL": "Poland", "PR": "Puerto Rico", "PS": "Palestine", "PT": "Portugal",
	"PY": "Paraguay", "QA": "Qatar", "RO": "Romania", "RS": "Serbia",
	"RU": "Russia", "RW": "Rwanda", "SA": "Saudi Arabia", "SD": "Sudan",
	"SE": "Sweden", "SI": "Slovenia", "SK": "Slovakia", "SL": "Sierra Leone",
	"SN": "Senegal", "SO": "Somalia", "SR": "Suriname", "SS": "South Sudan",
	"SV": "El Salvador", "SY": "Syria", "SZ": "Eswatini", "TD": "Chad",
	"TF": "Fr. South Territories", "TG": "Togo", "TH": "Thailand", "TJ": "Tajikistan",
	"TL": "Timor-Leste", "TM": "Turkmenistan", "TN": "Tunisia", "TR": "Turkey",
	"TW": "Taiwan", "TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda",
	"US": "United States", "UY": "Uruguay", "UZ": "Uzbekistan", "VE": "Venezuela",
	"VN": "Vietnam", "YE": "Yemen", "ZA": "South Africa", "ZM": "Zambia",
	"ZW": "Zimbabwe", "SG": "Singapore", "HK": "Hong Kong", "MO": "Macao",
	"LU": "Luxembourg", "MT": "Malta", "LI": "Liechtenstein", "AD": "Andorra",
	"MC": "Monaco", "SM": "San Marino", "VA": "Vatican", "MV": "Maldives",
	"BB": "Barbados", "JM": "Jamaica", "TT": "Trinidad & Tobago", "BS": "Bahamas",
	"AG": "Antigua & Barbuda", "DM": "Dominica", "GD": "Grenada", "KN": "St Kitts",
	"LC": "St Lucia", "VC": "St Vincent", "SC": "Seychelles", "KM": "Comoros",
	"MU": "Mauritius", "CV": "Cape Verde", "ST": "Sao Tome", "MP": "N. Mariana Is.",
}
