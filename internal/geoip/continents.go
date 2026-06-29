package geoip

// Continent support is implemented panel-side: the caddy-maxmind-geolocation
// module only matches on COUNTRY (allow_countries/deny_countries), so emitting
// allow_continents/deny_continents would be an unknown config key and reject the
// node's /load. Instead the panel expands each selected continent to its member
// ISO 3166-1 alpha-2 codes at config-generation time and merges them into the
// country list. Transcontinental countries follow MaxMind's assignment (e.g.
// RU->EU, TR/CY/AM/AZ/GE->AS).

// continentCountries maps a MaxMind continent code to its member country codes.
var continentCountries = map[string][]string{
	"AF": {"DZ", "AO", "BJ", "BW", "BF", "BI", "CM", "CV", "CF", "TD", "KM", "CG", "CD", "CI", "DJ", "EG", "GQ", "ER", "SZ", "ET", "GA", "GM", "GH", "GN", "GW", "KE", "LS", "LR", "LY", "MG", "MW", "ML", "MR", "MU", "YT", "MA", "MZ", "NA", "NE", "NG", "RE", "RW", "SH", "ST", "SN", "SC", "SL", "SO", "ZA", "SS", "SD", "TZ", "TG", "TN", "UG", "EH", "ZM", "ZW"},
	"AN": {"AQ", "BV", "GS", "HM", "TF"},
	"AS": {"AF", "AM", "AZ", "BH", "BD", "BT", "BN", "KH", "CN", "CY", "GE", "HK", "IN", "ID", "IR", "IQ", "IL", "JP", "JO", "KZ", "KP", "KR", "KW", "KG", "LA", "LB", "MO", "MY", "MV", "MN", "MM", "NP", "OM", "PK", "PS", "PH", "QA", "SA", "SG", "LK", "SY", "TW", "TJ", "TH", "TL", "TR", "TM", "AE", "UZ", "VN", "YE"},
	"EU": {"AL", "AD", "AT", "BY", "BE", "BA", "BG", "HR", "CZ", "DK", "EE", "FO", "FI", "FR", "DE", "GI", "GR", "GG", "HU", "IS", "IE", "IM", "IT", "JE", "XK", "LV", "LI", "LT", "LU", "MT", "MD", "MC", "ME", "NL", "MK", "NO", "PL", "PT", "RO", "RU", "SM", "RS", "SK", "SI", "ES", "SE", "CH", "UA", "GB", "VA", "AX", "SJ"},
	"NA": {"AI", "AG", "AW", "BS", "BB", "BZ", "BM", "BQ", "CA", "KY", "CR", "CU", "CW", "DM", "DO", "SV", "GL", "GD", "GP", "GT", "HT", "HN", "JM", "MQ", "MX", "MS", "NI", "PA", "PR", "BL", "KN", "LC", "MF", "PM", "VC", "SX", "TT", "TC", "US", "VG", "VI"},
	"OC": {"AS", "AU", "CK", "FJ", "PF", "GU", "KI", "MH", "FM", "NR", "NC", "NZ", "NU", "NF", "MP", "PW", "PG", "PN", "WS", "SB", "TK", "TO", "TV", "UM", "VU", "WF"},
	"SA": {"AR", "BO", "BR", "CL", "CO", "EC", "FK", "GF", "GY", "PY", "PE", "SR", "UY", "VE"},
}

// Continent is a continent option for the geo-block UI.
type Continent struct {
	Code string
	Name string
}

// continentNames is the display order + labels for the geo-block UI.
var continentNames = []Continent{
	{"AF", "Africa"},
	{"AS", "Asia"},
	{"EU", "Europe"},
	{"NA", "North America"},
	{"SA", "South America"},
	{"OC", "Oceania"},
	{"AN", "Antarctica"},
}

// Continents returns the selectable continents for the UI, in display order.
func Continents() []Continent { return continentNames }

// CountriesInContinent returns the ISO alpha-2 codes of a continent (uppercased
// continent code), or nil for an unknown continent.
func CountriesInContinent(code string) []string {
	return continentCountries[code]
}
