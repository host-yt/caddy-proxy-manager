package handlers

import (
	"context"
	"database/sql"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/geoip"
)

const worldmapNodeLimit = 500

// worldmapNodeHealth maps a health_status string to a rollup tier.
// "healthy" wins only when ALL nodes in a country are healthy.
func worldmapNodeHealth(statuses []string) string {
	if len(statuses) == 0 {
		return "down"
	}
	worst := "healthy"
	for _, s := range statuses {
		switch s {
		case "degraded":
			if worst == "healthy" {
				worst = "degraded"
			}
		case "down", "unknown":
			worst = "down"
		}
	}
	return worst
}

// worldmapCountryEntry holds aggregated node data for one country.
type worldmapCountryEntry struct {
	Code      string // ISO alpha-2 upper, e.g. "DE"
	Name      string // human-readable country name
	NodeCount int
	Health    string // "healthy" | "degraded" | "down"
	Nodes     []worldmapNodeEntry
}

// worldmapNodeEntry is a single caddy node row for the list below the map.
type worldmapNodeEntry struct {
	ID           int64
	Name         string
	PublicIP     string
	HealthStatus string
	IsEnabled    bool
}

type worldmapData struct {
	baseAdminData
	Countries      []*worldmapCountryEntry // countries with nodes, sorted by name
	CountryJSON    string                  // JS-safe JSON blob for map coloring
	Unknown        []*worldmapNodeEntry    // nodes whose country could not be resolved
	GeoIPAvailable bool
	DBUnavailable  bool
	WorldSVG       template.HTML // inlined world SVG; CSP blocks object-src so we inline
}

// AdminWorldMap renders the world map page showing caddy node locations.
func (h *AdminHandlers) AdminWorldMap(w http.ResponseWriter, r *http.Request) {
	d := worldmapData{baseAdminData: h.base(r, "Node world map")}
	d.PageDesc = "Geographic distribution of Caddy edge nodes."
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

	// Compute per-country rollup health and sort.
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

	// Build compact JSON for JS map coloring: {"DE":"healthy","US":"degraded",...}
	d.CountryJSON = buildCountryJSON(d.Countries)

	h.render(w, "worldmap", d)
}

func loadWorldmapNodes(ctx context.Context, db *sql.DB) []*worldmapNodeEntry {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, COALESCE(public_ip,''), health_status, is_enabled
		 FROM caddy_nodes
		 ORDER BY id DESC LIMIT ?`, worldmapNodeLimit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*worldmapNodeEntry
	for rows.Next() {
		var n worldmapNodeEntry
		var enabled int
		if err := rows.Scan(&n.ID, &n.Name, &n.PublicIP, &n.HealthStatus, &enabled); err == nil {
			n.IsEnabled = enabled == 1
			out = append(out, &n)
		}
	}
	return out
}

// buildCountryJSON emits {"DE":"healthy","US":"down"} without encoding/json import.
func buildCountryJSON(countries []*worldmapCountryEntry) string {
	var sb strings.Builder
	sb.WriteByte('{')
	for i, c := range countries {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte('"')
		sb.WriteString(c.Code)
		sb.WriteString(`":"`)
		sb.WriteString(c.Health)
		sb.WriteByte('"')
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
