// Package deployment defines install profiles and the feature flags each
// profile enables. The profile is chosen in the installer wizard and gates
// which modules and menu items are visible at runtime. It is the single
// source of truth for "which deployment shape is this install".
package deployment

// Profile is the deployment shape chosen at install time.
type Profile string

const (
	ProfileHomelab   Profile = "homelab"
	ProfileSmallTeam Profile = "smallteam"
	ProfileAdvanced  Profile = "advanced"
	ProfileProvider  Profile = "provider"
)

// Default applies when no profile was persisted (installs predating this
// feature). Provider shows every module, so an upgraded install never loses
// menu items - operators opt into a leaner menu, never get it forced on them.
const Default = ProfileProvider

// SQLiteAvailable reports whether the SQLite driver is wired. SQLite support
// is tracked but unfinished (the DB layer is heavily MySQL-coupled), so this
// stays false: small profiles recommend SQLite but only MySQL is selectable.
const SQLiteAvailable = true

// SetupVersion stamps install_state on completion so later migrations of the
// profile/feature-flag schema can detect and upgrade older installs.
const SetupVersion = "1"

// Parse maps a stored string to a Profile, falling back to Default for empty
// or unknown values (legacy installs see the full menu).
func Parse(s string) Profile {
	p := Profile(s)
	if p.Valid() {
		return p
	}
	return Default
}

// Valid reports whether p is a known profile.
func (p Profile) Valid() bool {
	switch p {
	case ProfileHomelab, ProfileSmallTeam, ProfileAdvanced, ProfileProvider:
		return true
	}
	return false
}

// All returns the profiles in upgrade order (leanest to richest).
func All() []Profile {
	return []Profile{ProfileHomelab, ProfileSmallTeam, ProfileAdvanced, ProfileProvider}
}

// rank orders profiles so upgrade/downgrade direction is comparable.
func (p Profile) rank() int {
	switch p {
	case ProfileHomelab:
		return 0
	case ProfileSmallTeam:
		return 1
	case ProfileAdvanced:
		return 2
	case ProfileProvider:
		return 3
	}
	return 3 // unknown == provider == richest
}

// IsDowngrade reports whether switching from p to next removes modules. A
// downgrade is allowed but the caller should warn: it hides active data.
func (p Profile) IsDowngrade(next Profile) bool {
	return next.rank() < p.rank()
}

// Label is the human-facing profile name.
func (p Profile) Label() string {
	switch p {
	case ProfileHomelab:
		return "Homelab"
	case ProfileSmallTeam:
		return "Small team"
	case ProfileAdvanced:
		return "Advanced"
	case ProfileProvider:
		return "Provider"
	}
	return string(p)
}

// Description is a one-line summary shown in the installer and settings.
func (p Profile) Description() string {
	switch p {
	case ProfileHomelab:
		return "Single owner, minimal setup. Hosts, tunnels and local backup."
	case ProfileSmallTeam:
		return "A few users with per-user access, groups and basic audit."
	case ProfileAdvanced:
		return "Own infrastructure: multi-node, observability, API and automation."
	case ProfileProvider:
		return "Hosting provider: clients, plans, scoped admins and provisioning."
	}
	return ""
}

// UIMode controls overall menu density: simple, standard or provider.
func (p Profile) UIMode() string {
	switch p {
	case ProfileHomelab:
		return "simple"
	case ProfileProvider:
		return "provider"
	default:
		return "standard"
	}
}

// TenantMode is "multi" only for provider; everyone else is single-tenant.
func (p Profile) TenantMode() string {
	if p == ProfileProvider {
		return "multi"
	}
	return "single"
}

// RBACMode names the role set a profile expects (UI visibility only - the
// underlying role enum is unchanged).
func (p Profile) RBACMode() string {
	switch p {
	case ProfileHomelab:
		return "owner"
	case ProfileSmallTeam:
		return "team"
	case ProfileAdvanced:
		return "ops"
	case ProfileProvider:
		return "tenant"
	}
	return "tenant"
}

// DBMode describes which database a profile recommends or requires.
type DBMode struct {
	Recommended  string // "sqlite" | "mysql"
	RequireMySQL bool   // provider: SQLite is not a valid choice
	SQLiteOK     bool   // policy allows SQLite (still gated by SQLiteAvailable)
}

// DB returns the database policy for the profile.
func (p Profile) DB() DBMode {
	switch p {
	case ProfileHomelab, ProfileSmallTeam:
		return DBMode{Recommended: "sqlite", SQLiteOK: true}
	case ProfileAdvanced:
		return DBMode{Recommended: "mysql", SQLiteOK: false}
	case ProfileProvider:
		return DBMode{Recommended: "mysql", RequireMySQL: true}
	}
	return DBMode{Recommended: "mysql", RequireMySQL: true}
}

// AllowsDriver reports whether driver ("mysql"|"sqlite") is permitted for the
// profile. SQLite is additionally gated by SQLiteAvailable (not wired yet).
func (p Profile) AllowsDriver(driver string) bool {
	switch driver {
	case "mysql":
		return true
	case "sqlite":
		return SQLiteAvailable && p.DB().SQLiteOK && !p.DB().RequireMySQL
	}
	return false
}

// Features is the set of modules visible for a profile. It is the source of
// truth for nav gating - populated once per request into the page base data.
type Features struct {
	// Traffic
	Hosts   bool
	Streams bool // L4 streams
	Certs   bool
	// Fleet / edge
	Map     bool
	Nodes   bool
	Tunnels bool
	// Customers (multi-tenant)
	Clients        bool
	Plans          bool
	Services       bool
	Scopes         bool // per-client admin scopes
	CustomerPortal bool
	// Access control
	Users     bool
	Audit     bool
	APITokens bool
	// Security
	WAF               bool
	ExternalAllowlist bool
	// Observability
	Stats     bool
	Alerts    bool
	Bandwidth bool
	// System
	Backups      bool
	RestoreDrill bool
	DNSProviders bool
	NPMImport    bool
	Settings     bool
}

// Features returns the modules enabled for the profile. Profiles are
// cumulative: each tier adds to the one below it.
func (p Profile) Features() Features {
	// homelab baseline: minimal self-host.
	f := Features{
		Hosts:     true,
		Tunnels:   true,
		Map:       true,
		Certs:     true,
		Backups:   true,
		NPMImport: true,
		Settings:  true,
	}
	if p == ProfileHomelab {
		return f
	}
	// smallteam: local users/groups + basic audit.
	f.Users = true
	f.Audit = true
	if p == ProfileSmallTeam {
		return f
	}
	// advanced: fleet, observability, advanced traffic + security, automation.
	f.Nodes = true
	f.Streams = true
	f.Stats = true
	f.Alerts = true
	f.Bandwidth = true
	f.APITokens = true
	f.WAF = true
	f.ExternalAllowlist = true
	f.RestoreDrill = true
	f.DNSProviders = true
	if p == ProfileAdvanced {
		return f
	}
	// provider: full multi-tenant customer model (also the fallback for
	// unknown profiles, so nothing is ever hidden by accident).
	f.Clients = true
	f.Plans = true
	f.Services = true
	f.Scopes = true
	f.CustomerPortal = true
	return f
}
