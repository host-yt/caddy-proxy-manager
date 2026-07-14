// Package config loads runtime configuration from environment variables.
//
// Source of truth: env. .env file is loaded only in development (when present)
// to avoid surprises in production where secrets come from the orchestrator.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	App      AppConfig
	Install  InstallConfig
	DB       DBConfig
	Redis    RedisConfig
	Caddy    CaddyConfig
	SMTP     SMTPConfig
	Security SecurityConfig
	OIDC     OIDCConfig
}

type AppConfig struct {
	Env            string
	URL            string
	Bind           string
	Secret         string
	TrustedProxies []string
	LogLevel       string

	// PanelInternalHost is the address Caddy nodes use to reach the panel
	// container on the internal network (docker compose service name, k8s
	// service name, or a static IP). Defaults to "app" because that's the
	// compose service name in deploy/docker-compose.yml.
	PanelInternalHost string
	PanelInternalPort int
}

type InstallConfig struct {
	Installed bool
	Token     string // INSTALL_TOKEN: gate state-changing wizard endpoints
}

type DBConfig struct {
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	TLS      bool
	DSN      string // optional override
	// Driver is the database driver: "mysql" or "sqlite3".
	Driver string
	// SQLitePath is the file path for the SQLite database (driver=sqlite3).
	// Env: DB_SQLITE_PATH. Default: ./data/hpg.db
	SQLitePath string
}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type CaddyConfig struct {
	AdminURL       string
	PublicHostname string
	PublicIP       string
	ACMEEmail      string
	ACMEStaging    bool
	// CacheHandlerAvailable is true when every target Caddy node runs the
	// custom image (deploy/caddy/Dockerfile, xcaddy build with
	// caddy-cache-handler). Flipping this on before fleet upgrade will
	// cause stock caddy:2.8 nodes to reject the entire config (unknown
	// app `cache`) and go offline. Env: CACHE_HANDLER_AVAILABLE=1.
	CacheHandlerAvailable bool
	// Layer4Available mirrors caddyapi.NodeSettings.Layer4ModuleAvailable.
	// Set when every Caddy node runs the custom image with caddy-l4.
	// Env: LAYER4_AVAILABLE=1.
	Layer4Available bool
	// WeightedLBAvailable gates the weighted_round_robin LB policy. round_robin/
	// least_conn/ip_hash + health checks are stock and need no gate. Env:
	// WEIGHTED_LB_AVAILABLE=1. Off = builder downgrades weighted to round_robin.
	WeightedLBAvailable bool
	// RateLimitAvailable gates per-route rate_limit emission (caddy-ratelimit).
	// Env: RATE_LIMIT_AVAILABLE=1. Needs the xcaddy module on every node.
	RateLimitAvailable bool
	// WAFModuleAvailable gates per-route coraza WAF emission. Env:
	// WAF_MODULE_AVAILABLE=1. Needs the xcaddy coraza module on every node.
	WAFModuleAvailable bool
	// DNS01Available gates wildcard DNS-01 automation policies (caddy-dns).
	// Env: DNS01_AVAILABLE=1. Needs the xcaddy DNS provider module on every node.
	DNS01Available bool
	// GeoIPAvailable gates the per-route geoip2 country matcher + geo blocking
	// handler. Env: GEOIP_AVAILABLE=1. Needs the maxmind/caddy-maxmind-geolocation
	// module on every node, else stock Caddy rejects the entire /load.
	GeoIPAvailable bool
}

type SMTPConfig struct {
	Host       string
	Port       int
	Encryption string // tls | ssl | none
	Username   string
	Password   string
	FromEmail  string
	FromName   string
}

type SecurityConfig struct {
	SessionCookieName     string
	SessionCookieSecure   bool
	SessionCookieSameSite string
	CSRFCookieName        string
	RateLimitLoginPerMin  int
	RateLimitAskPerMin    int
	CaptchaProvider       string
	CaptchaSiteKey        string
	CaptchaSecret         string
	SSOJumpSharedSecret   string
	// MetricsAllow restricts /metrics to a CIDR allow-list. Empty list
	// keeps the legacy behavior (open within the docker network); set it
	// in production to lock the endpoint down.
	MetricsAllow []string
	// FOSSBillingAllowIPs source-binds the /api/v1/provisioning endpoints to
	// the billing system's IP(s) (CIDR allow-list). Empty = no source
	// restriction (auth is still the API key). Set it to bind provisioning to
	// the billing host so a leaked admin key alone cannot provision (BILL-01).
	FOSSBillingAllowIPs []string
	// ExternalUpstreamAllowlist is the set of FQDNs an external-HTTPS-upstream
	// route may proxy to (exact host). Empty = external routes disabled. The
	// primary open-relay defense for the external-proxy feature.
	ExternalUpstreamAllowlist []string

	// AskAllowCIDRs source-binds /internal/ask (Caddy on-demand TLS) to a
	// CIDR allow-list. Empty = open (unchanged); avoids gating cert issuance
	// on APP_TRUSTED_PROXIES, which many deployments already set (C-01).
	AskAllowCIDRs []string

	// SIEMWebhook is the URL each audit event is POSTed to (JSON). Empty =
	// disabled. The forwarder's SafeHTTPClient blocks RFC1918/loopback.
	SIEMWebhook string

	// RequireAdmin2FA blocks admin/super_admin users without any 2FA enrolled
	// from /admin/* until they enroll. Env: REQUIRE_ADMIN_2FA=1. A DB settings
	// row (security.require_admin_2fa) hot-toggles it without a restart.
	RequireAdmin2FA bool
	// Admin2FAGraceHours is the break-glass window (hours) an existing admin
	// keeps access after enforcement first applies to them, so flipping the
	// policy on doesn't instantly lock anyone out. 0 = enforce immediately.
	Admin2FAGraceHours int
}

type OIDCConfig struct {
	Enabled      bool
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// Load reads env vars into Config and validates required fields.
func Load() (*Config, error) {
	c := loadEnv()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// LoadUnvalidated reads env vars into Config without enforcing required
// fields (APP_SECRET/APP_URL/DB creds). Doctor checks need the raw values
// (e.g. DB host/port) even when validation would fail, so a bad/missing
// APP_SECRET doesn't block every other preflight check from running.
func LoadUnvalidated() *Config {
	return loadEnv()
}

func loadEnv() *Config {
	c := &Config{
		App: AppConfig{
			Env:               envOr("APP_ENV", "production"),
			URL:               os.Getenv("APP_URL"),
			Bind:              envOr("APP_BIND", "0.0.0.0:8080"),
			Secret:            os.Getenv("APP_SECRET"),
			TrustedProxies:    splitCSV(os.Getenv("APP_TRUSTED_PROXIES")),
			LogLevel:          envOr("LOG_LEVEL", "info"),
			PanelInternalHost: envOr("APP_INTERNAL_HOST", "app"),
			PanelInternalPort: envInt("APP_INTERNAL_PORT", 8080),
		},
		Install: InstallConfig{
			Installed: envBool("INSTALLED", false),
			Token:     os.Getenv("INSTALL_TOKEN"),
		},
		DB: DBConfig{
			Host:       envOr("DB_HOST", "mariadb"),
			Port:       envInt("DB_PORT", 3306),
			Name:       envOr("DB_NAME", "hostyt_proxy"),
			User:       os.Getenv("DB_USER"),
			Password:   os.Getenv("DB_PASSWORD"),
			TLS:        envBool("DB_TLS", false),
			DSN:        os.Getenv("DB_DSN"),
			Driver:     envOr("DB_DRIVER", "mysql"),
			SQLitePath: envOr("DB_SQLITE_PATH", "./data/hpg.db"),
		},
		Redis: RedisConfig{
			Addr:     envOr("REDIS_ADDR", "redis:6379"),
			Password: os.Getenv("REDIS_PASSWORD"),
			DB:       envInt("REDIS_DB", 0),
		},
		Caddy: CaddyConfig{
			AdminURL:              envOr("CADDY_ADMIN_URL", "http://caddy:2019"),
			PublicHostname:        os.Getenv("CADDY_PUBLIC_HOSTNAME"),
			PublicIP:              os.Getenv("CADDY_PUBLIC_IP"),
			ACMEEmail:             os.Getenv("CADDY_ACME_EMAIL"),
			ACMEStaging:           envBool("CADDY_ACME_STAGING", false),
			CacheHandlerAvailable: envBool("CACHE_HANDLER_AVAILABLE", false),
			Layer4Available:       envBool("LAYER4_AVAILABLE", false),
			WeightedLBAvailable:   envBool("WEIGHTED_LB_AVAILABLE", false),
			RateLimitAvailable:    envBool("RATE_LIMIT_AVAILABLE", false),
			WAFModuleAvailable:    envBool("WAF_MODULE_AVAILABLE", false),
			DNS01Available:        envBool("DNS01_AVAILABLE", false),
			GeoIPAvailable:        envBool("GEOIP_AVAILABLE", false),
		},
		SMTP: SMTPConfig{
			Host:       os.Getenv("SMTP_HOST"),
			Port:       envInt("SMTP_PORT", 587),
			Encryption: envOr("SMTP_ENCRYPTION", "tls"),
			Username:   os.Getenv("SMTP_USERNAME"),
			Password:   os.Getenv("SMTP_PASSWORD"),
			FromEmail:  os.Getenv("SMTP_FROM_EMAIL"),
			FromName:   envOr("SMTP_FROM_NAME", "Hostyt Proxy"),
		},
		Security: SecurityConfig{
			SessionCookieName:         envOr("SESSION_COOKIE_NAME", "hpg_session"),
			SessionCookieSecure:       envBool("SESSION_COOKIE_SECURE", true),
			SessionCookieSameSite:     envOr("SESSION_COOKIE_SAMESITE", "lax"),
			CSRFCookieName:            envOr("CSRF_COOKIE_NAME", "hpg_csrf"),
			RateLimitLoginPerMin:      envInt("RATE_LIMIT_LOGIN_PER_MIN", 10),
			RateLimitAskPerMin:        envInt("RATE_LIMIT_ASK_PER_MIN", 120),
			CaptchaProvider:           os.Getenv("CAPTCHA_PROVIDER"),
			CaptchaSiteKey:            os.Getenv("CAPTCHA_SITE_KEY"),
			CaptchaSecret:             os.Getenv("CAPTCHA_SECRET"),
			SSOJumpSharedSecret:       os.Getenv("SSO_JUMP_SHARED_SECRET"),
			MetricsAllow:              splitCSV(os.Getenv("APP_METRICS_ALLOW")),
			FOSSBillingAllowIPs:       splitCSV(os.Getenv("FOSSBILLING_ALLOW_IPS")),
			ExternalUpstreamAllowlist: splitCSV(os.Getenv("EXTERNAL_UPSTREAM_ALLOWLIST")),
			AskAllowCIDRs:             splitCSV(os.Getenv("ASK_ALLOW_CIDRS")),
			SIEMWebhook:               os.Getenv("AUDIT_SIEM_WEBHOOK"),
			RequireAdmin2FA:           envBool("REQUIRE_ADMIN_2FA", false),
			Admin2FAGraceHours:        envInt("REQUIRE_ADMIN_2FA_GRACE_HOURS", 0),
		},
		OIDC: OIDCConfig{
			Enabled:      envBool("OIDC_ENABLED", false),
			Issuer:       os.Getenv("OIDC_ISSUER"),
			ClientID:     os.Getenv("OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("OIDC_REDIRECT_URL"),
		},
	}

	return c
}

func (c *Config) validate() error {
	// Unconditional: the wizard only flips data/install_state.json, never
	// INSTALLED env, so gating on Install.Installed never actually ran this
	// check. APP_SECRET is HKDF input for the install-state AES key, backup
	// key, and API-key HMAC - must be strong from first boot.
	if len(c.App.Secret) < 32 {
		return errors.New("APP_SECRET must be set (>=32 chars)")
	}
	if c.App.URL == "" {
		return errors.New("APP_URL is required")
	}
	if c.Install.Installed && c.DB.Driver != "sqlite3" {
		if c.DB.DSN == "" && (c.DB.User == "" || c.DB.Password == "") {
			return errors.New("DB credentials missing (DB_USER/DB_PASSWORD or DB_DSN)")
		}
	}
	return nil
}

// BuildDSN returns a MySQL DSN string for go-sql-driver/mysql.
func (d DBConfig) BuildDSN() string {
	if d.DSN != "" {
		return d.DSN
	}
	tls := ""
	if d.TLS {
		tls = "&tls=true"
	}
	// time_zone='+00:00' pins the session to UTC so UNIX_TIMESTAMP()/NOW() agree
	// with the UTC values Go writes (loc=UTC); otherwise time-bucketed analytics
	// queries key on the server's local TZ and render empty.
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC&time_zone=%%27%%2B00%%3A00%%27&charset=utf8mb4%s",
		d.User, d.Password, d.Host, d.Port, d.Name, tls)
}

// BuildSQLiteDSN returns the modernc.org/sqlite DSN for the configured path.
func (d DBConfig) BuildSQLiteDSN() string {
	path := d.SQLitePath
	if path == "" {
		path = "./data/hpg.db"
	}
	// WAL mode for better concurrent reads; foreign_keys on; busy_timeout for write lock.
	return "file:" + path + "?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000"
}

// --- helpers --------------------------------------------------------------

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envBool(k string, def bool) bool {
	v := strings.ToLower(os.Getenv(k))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
