// Package httpserver wires the HTTP router, middleware, and handlers.
package httpserver

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/accesslog"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/config"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/handlers"
	mw "github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/obs"
)

type Deps struct {
	Config       *config.Config
	Logger       *slog.Logger
	InstallState *installstate.Manager
	Sessions     *auth.Manager
	Wizard       *handlers.Wizard
	Auth         *handlers.AuthHandlers
	Admin        *handlers.AdminHandlers
	Client       *handlers.ClientHandlers
	Portal       *handlers.PortalHandlers
	Ask          *handlers.AskHandler
	API          *handlers.APIHandlers
	APIDocs      *handlers.APIDocsHandler
	Passkey      *handlers.PasskeyHandlers
	NodeJoin     *handlers.NodeJoinHandler
	WGBoot       *handlers.WGBootstrapHandler
	NodeGeoIP    *handlers.NodeGeoIPHandler
	TrustCFIP    func() bool // returns true when CF-Connecting-IP should be honoured
	Metrics      *obs.Metrics
	Health       *obs.Health
	RDB          *redis.Client
	// StaticFS, when set, serves /static/* from the embedded asset tree so
	// the binary is self-contained (works regardless of CWD). nil falls back
	// to reading web/static from disk.
	StaticFS fs.FS
	// WorldSVGSubFS is the sub-FS rooted at web/static/ used to load the
	// world map SVG for inline embedding (bypasses object-src CSP block).
	WorldSVGSubFS fs.FS
	DB            func() *http.Request // unused; kept type-compatible if needed
	// StatusPage serves the public per-client status page (no auth).
	StatusPage *handlers.StatusPageHandlers
	// FOSSBilling drives the /api/v1/provisioning/* endpoints called by FOSSBilling.
	FOSSBilling *handlers.FOSSBillingHandlers

	// AccessLogIngest receives structured access-log JSON POSTed by Caddy nodes.
	AccessLogIngest *accesslog.IngestHandler

	// OAuthIdentity handles the linked-provider list + unlink endpoints.
	OAuthIdentity *handlers.OAuthIdentityHandlers

	// NodeWAFIngest receives WAF event batches POSTed by node-local Caddy WAF modules.
	NodeWAFIngest *handlers.NodeWAFIngestHandler
}

type Server struct {
	deps Deps
	mux  *chi.Mux
}

func New(d Deps) *Server {
	s := &Server{deps: d, mux: chi.NewRouter()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

// admin2FARequired reads the runtime DB toggle (security.require_admin_2fa) so
// operators can flip 2FA enforcement without a restart. Best-effort: a missing
// row or unavailable DB means "not required" (the env var still applies).
func (s *Server) admin2FARequired() bool {
	db := s.deps.Wizard.DB()
	if db == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var v string
	_ = db.QueryRowContext(ctx, "SELECT value FROM settings WHERE `key` = 'security.require_admin_2fa' LIMIT 1").Scan(&v)
	return v == "1"
}

func (s *Server) routes() {
	// Wire the world SVG FS so the worldmap handler can inline the SVG.
	// Must happen before any request; routes() is called from New() at startup.
	if s.deps.WorldSVGSubFS != nil {
		handlers.WorldSVGFS = s.deps.WorldSVGSubFS
	}

	r := s.mux

	r.Use(chimw.RequestID)
	r.Use(mw.TraceID) // echo request id into X-Request-Id response header
	// TrustedRealIP replaces chi's blind RealIP - only honors XFF / X-Real-IP
	// / True-Client-IP when the immediate peer is in APP_TRUSTED_PROXIES.
	// Empty list = headers ignored, RemoteAddr stays as the raw peer.
	r.Use(mw.TrustedRealIP(mw.ParseCIDRList(s.deps.Config.App.TrustedProxies)))
	r.Use(mw.CloudflareIP(s.deps.TrustCFIP))
	r.Use(chimw.Recoverer)
	r.Use(mw.SecurityHeaders)
	if s.deps.Metrics != nil {
		r.Use(s.deps.Metrics.Middleware)
	}
	r.Use(slogRequestLogger(s.deps.Logger))
	r.Use(chimw.Timeout(30_000_000_000))
	r.Use(installRedirectMiddleware(s.deps.InstallState))
	r.Use(mw.LoadSession(s.deps.Sessions))
	r.Use(mw.VerifyCSRF)
	// Global anti-DDoS: cap unauthenticated POST traffic per source IP.
	// Authenticated sessions are skipped (admin workflows hit their own
	// per-handler limits). 60/min/IP fits real users behind NAT (office,
	// VPN, mobile carrier) while still throttling brute force; the
	// per-(email,IP) lockout in handlers/auth.go does the targeted job.
	if s.deps.RDB != nil {
		r.Use(mw.UnauthPostLimit(s.deps.RDB, 60))
	}

	if s.deps.Health != nil {
		r.Get("/healthz", s.deps.Health.Live)
		r.Get("/readyz", s.deps.Health.Ready)
	} else {
		r.Get("/healthz", handlers.Health)
		r.Get("/readyz", handlers.Ready)
	}
	if s.deps.Metrics != nil {
		// /metrics is panel ops surface. When APP_METRICS_ALLOW is set the
		// endpoint refuses traffic from outside that CIDR list - relying on
		// a firewall alone is brittle for a self-hosted product.
		metricsAllow := mw.ParseCIDRList(s.deps.Config.Security.MetricsAllow)
		r.Handle("/metrics", mw.IPAllowList(metricsAllow, s.deps.Metrics.Handler()))
	}
	r.Get("/favicon.ico", handlers.Favicon)

	// Public API docs - no auth, open to all.
	if s.deps.APIDocs != nil {
		r.Get("/api-docs", s.deps.APIDocs.Page)
		r.Get("/api-docs/openapi.json", s.deps.APIDocs.Spec)
	} else {
		r.Get("/api-docs", handlers.APIDocsPage)
		r.Get("/api-docs/openapi.json", handlers.APIDocsSpec)
	}

	// Language switcher - sets cookie, redirects to referer.
	r.Get("/lang/{code}", handlers.LangSwitch)

	// Palette theme switcher - sets cookie, redirects to referer.
	r.Get("/theme/{slug}", handlers.ThemeSwitch)

	// Public legal documents (ToS, privacy policy, etc.) - no auth.
	r.Get("/legal/{slug}", handlers.LegalDocPublic(s.deps.Wizard.DB))
	// Public per-client status pages - rate-limited, no auth.
	r.Group(func(r chi.Router) {
		r.Use(mw.RateLimit(mw.RateLimitConfig{
			RDB:         s.deps.RDB,
			PerIPPerMin: 20,
			KeyPrefix:   "hpg:rl:status",
		}))
		r.Get("/status/{slug}", s.deps.StatusPage.Page)
	})

	// Customer-facing docs served from the panel (markdown rendered).
	r.Get("/docs/{slug}", handlers.PublicDoc())

	// Public node bootstrap script - content is non-secret; only useful
	// in combination with a one-time join token.
	r.Get("/install/node.sh", s.deps.NodeJoin.Script)

	r.Get("/internal/ask", s.deps.Ask.ServeHTTP)
	if s.deps.AccessLogIngest != nil {
		r.Post("/internal/access-log", s.deps.AccessLogIngest.ServeHTTP)
	}

	// Customer-WG public endpoints. Bootstrap token (24h, single-shot)
	// gates the .conf + installer; node-agent uses Bearer node_token.
	if s.deps.WGBoot != nil {
		r.Get("/api/wg/bootstrap", s.deps.WGBoot.BootstrapConf)
		r.Get("/api/wg/install.sh", s.deps.WGBoot.InstallScript)
		r.Get("/api/wg/status", s.deps.WGBoot.PeerStatus)
		r.Get("/api/node/wg/peers", s.deps.WGBoot.NodePeersPull)
		r.Post("/api/node/wg/handshakes", s.deps.WGBoot.NodeHandshakeReport)
		r.Post("/api/node/wg/stats", s.deps.WGBoot.NodePeerStatsReport)
	}

	// GeoIP DB distribution: node-agents pull the central mmdb over the tunnel.
	if s.deps.NodeGeoIP != nil {
		r.Get("/api/node/geoip/meta", s.deps.NodeGeoIP.Meta)
		r.Get("/api/node/geoip/mmdb", s.deps.NodeGeoIP.MMDB)
	}

	// WAF event ingest: custom Caddy WAF module ships batches to the panel.
	if s.deps.NodeWAFIngest != nil {
		r.Post("/api/node/waf/events", s.deps.NodeWAFIngest.Ingest)
	}

	// Install wizard. State-changing routes go through InstallGuard.
	r.Route("/install", func(r chi.Router) {
		r.Get("/", s.deps.Wizard.Index)
		r.Group(func(r chi.Router) {
			r.Use(mw.InstallGuard(s.deps.InstallState.IsInstalled, s.deps.Config.Install.Token))
			r.Post("/start", s.deps.Wizard.Start)
			r.Post("/profile", s.deps.Wizard.ProfileSubmit)
			r.Post("/db", s.deps.Wizard.DBSubmit)
			r.Post("/admin", s.deps.Wizard.AdminSubmit)
			r.Post("/app", s.deps.Wizard.AppSubmit)
			r.Post("/smtp", s.deps.Wizard.SMTPSubmit)
			r.Post("/caddy", s.deps.Wizard.CaddySubmit)
		})
	})

	// Auth.
	r.Route("/auth", func(r chi.Router) {
		r.Get("/login", s.deps.Auth.LoginPage)
		r.Post("/login", s.deps.Auth.LoginSubmit)
		r.Post("/logout", s.deps.Auth.Logout)
		r.Post("/end-impersonation", s.deps.Auth.EndImpersonation)
		r.Get("/forgot", s.deps.Auth.ForgotPage)
		r.Post("/forgot", s.deps.Auth.ForgotSubmit)
		r.Get("/reset", s.deps.Auth.ResetPage)
		r.Post("/reset", s.deps.Auth.ResetSubmit)
		r.Get("/2fa", s.deps.Auth.TOTPChallenge)
		r.Post("/2fa", s.deps.Auth.TOTPVerify)
		r.Post("/2fa/send", s.deps.Auth.TwoFASend)
		r.Get("/sms-otp", s.deps.Auth.SMSOTPChallenge)
		r.Post("/sms-otp", s.deps.Auth.SMSOTPVerify)
		r.Get("/email-otp", s.deps.Auth.EmailOTPChallenge)
		r.Post("/email-otp", s.deps.Auth.EmailOTPVerify)
		if s.deps.Passkey != nil {
			r.Post("/passkey/login/begin", s.deps.Passkey.LoginBegin)
			r.Post("/passkey/login/finish", s.deps.Passkey.LoginFinish)
		}
		r.Get("/oidc/start", s.deps.Auth.OIDCStart)
		r.Get("/oidc/callback", s.deps.Auth.OIDCCallback)
		// Social login (GitHub, Google) alongside OIDC. Provider in the path;
		// handlers reject unsupported slugs with 404.
		r.Get("/{provider}/start", s.deps.Auth.OAuth2Start)
		r.Get("/{provider}/callback", s.deps.Auth.OAuth2Callback)
		r.Get("/sso/jump", s.deps.Auth.SSOJump)
	})

	// Built-in forward-auth portal. Public (served on the PROTECTED host via
	// Caddy forward_auth + /hpg-portal/* passthrough), no panel session. The
	// verify endpoint is what Caddy calls; login mints the portal cookie.
	// CSRF middleware skips these (no panel session on this origin) - the
	// login form relies on SameSite=Lax + the per-(email,IP) lockout, same as
	// /auth/login.
	if s.deps.Portal != nil {
		r.Route("/hpg-portal", func(r chi.Router) {
			r.Get("/verify", s.deps.Portal.Verify)
			r.Get("/login", s.deps.Portal.LoginPage)
			r.Post("/login", s.deps.Portal.LoginSubmit)
			r.Post("/logout", s.deps.Portal.Logout)
			r.Get("/logout", s.deps.Portal.Logout)
		})
	}

	// Admin panel. Support is admitted through a strict read-only allow-list
	// below; admin/super_admin keep the full surface.
	r.Route("/admin", func(r chi.Router) {
		r.Use(mw.RequireRole("super_admin", "admin", "support"))
		r.Use(mw.ReadOnlyRoleAllowList("support", []string{
			"/admin/map",
			"/admin/worldmap",
			"/admin/tunnels",
			"/admin/tunnels/*/bandwidth.json",
			"/admin/hosts/*/logs",
			"/admin/hosts/*/logs.json",
			"/admin/hosts/*/logs/stream",
			"/admin/hosts/*/logs/export",
			"/admin/waf",
			"/admin/waf.json",
			"/admin/waf/export",
			// AI assistant is read-only (tools are SELECT-only); support may use it.
			"/admin/ai/chat",
			"/admin/ai/chat/sessions",
			"/admin/ai/chat/sessions/*",
			"/admin/ai/chat/sessions/*/message",
		}, []string{
			// Writes the assistant needs to persist its own conversation. Safe:
			// the tools it can run are read-only and never mutate HPG state.
			"/admin/ai/chat/sessions",
			"/admin/ai/chat/sessions/*",
			"/admin/ai/chat/sessions/*/message",
		}))
		// Enforce 2FA enrollment for admins when REQUIRE_ADMIN_2FA (env) or the
		// security.require_admin_2fa settings row is on. Bypasses enrollment +
		// logout routes internally; grace window avoids an instant lock-out.
		r.Use(mw.RequireAdmin2FA(
			s.deps.Wizard.DB,
			s.deps.RDB,
			func() bool { return s.deps.Config.Security.RequireAdmin2FA || s.admin2FARequired() },
			s.deps.Config.Security.Admin2FAGraceHours,
		))
		r.Get("/2fa/required", s.deps.Admin.TwoFARequired)
		r.Get("/", s.deps.Admin.Dashboard)
		r.Get("/map", s.deps.Admin.AdminMap)
		r.Get("/worldmap", s.deps.Admin.AdminWorldMap)
		r.Get("/stats", s.deps.Admin.Stats)
		// Deployment mode (install profile). View is read-only for any admin;
		// the POST handler enforces super_admin internally.
		r.Get("/deployment", s.deps.Admin.DeploymentPage)
		r.Post("/deployment", s.deps.Admin.DeploymentUpdate)
		r.Route("/nodes", func(r chi.Router) {
			r.Get("/", s.deps.Admin.Nodes)
			r.Get("/{id}", s.deps.Admin.NodeDetail)
			r.Get("/{id}/edit", s.deps.Admin.NodesEdit)
			r.Post("/{id}/edit", s.deps.Admin.NodesUpdate)
			r.Post("/", s.deps.Admin.NodesCreate)
			r.Post("/join-token", s.deps.Admin.NodesJoinToken)
			r.Post("/apply-wg", s.deps.Admin.NodesApplyWG)
			r.Post("/{id}/toggle", s.deps.Admin.NodesToggle)
			r.Post("/{id}/delete", s.deps.Admin.NodesDelete)
			r.Post("/{id}/resync", s.deps.Admin.NodesResync)
			r.Post("/{id}/approve", s.deps.Admin.NodesApprove)
			r.Post("/{id}/decommission", s.deps.Admin.NodesDecommission)
			r.Post("/{id}/rekey", s.deps.Admin.NodesRekey)
			r.Post("/{id}/probe-capabilities", s.deps.Admin.ProbeNodeCapabilities)
			r.Get("/{id}/failover-preview", s.deps.Admin.FailoverPreview)
			r.Get("/{id}/preflight.json", s.deps.Admin.NodePreflight)
		})
		r.Get("/certs", s.deps.Admin.CertsList)
		r.Route("/manual-certs", func(r chi.Router) {
			r.Get("/", s.deps.Admin.ManualCertsList)
			r.Post("/import", s.deps.Admin.ManualCertsImport)
			r.Post("/{id}/delete", s.deps.Admin.ManualCertsDelete)
			r.Post("/{id}/replace", s.deps.Admin.ManualCertsReplace)
		})
		// mTLS CA scaffold: per-tenant CAs + client cert issue/revoke.
		r.Route("/mtls", func(r chi.Router) {
			r.Get("/", s.deps.Admin.MTLSList)
			r.Post("/ca", s.deps.Admin.MTLSCreateCA)
			r.Post("/ca/{id}/delete", s.deps.Admin.MTLSDeleteCA)
			r.Post("/ca/{id}/issue", s.deps.Admin.MTLSIssue)
			r.Get("/ca/{id}/bundle.pem", s.deps.Admin.MTLSCABundle)
			r.Get("/ca/{id}/crl", s.deps.Admin.MTLSCRL)
			r.Post("/cert/{id}/revoke", s.deps.Admin.MTLSRevoke)
		})
		r.Get("/branding", s.deps.Admin.BrandingPage)
		r.Post("/branding", s.deps.Admin.BrandingSave)
		r.Route("/hosts", func(r chi.Router) {
			r.Get("/", s.deps.Admin.HostsList)
			r.Get("/export.csv", s.deps.Admin.HostsExport)
			r.Get("/new", s.deps.Admin.HostsNew)
			r.Post("/new", s.deps.Admin.HostsCreate)
			r.Get("/check-dns", s.deps.Admin.HostsCheckDNS)
			r.Post("/{id}/purge-cache", s.deps.Admin.HostsPurgeCache)
			r.Post("/{id}/clone", s.deps.Admin.HostsClone)
			r.Get("/{id}/edit", s.deps.Admin.HostsEdit)
			r.Post("/{id}/edit", s.deps.Admin.HostsUpdate)
			r.Post("/{id}/regenerate-secret", s.deps.Admin.HostsRegenerateSecret)
			r.Post("/{id}/reveal-secret", s.deps.Admin.HostsRevealSecret)
			r.Post("/{id}/delete", s.deps.Admin.HostsDelete)
			r.Post("/{id}/toggle", s.deps.Admin.HostsToggle)
			r.Post("/{id}/toggle-maintenance", s.deps.Admin.HostsToggleMaintenance)
			r.Post("/{id}/retry", s.deps.Admin.HostsRetry)
			r.Post("/bulk", s.deps.Admin.HostsBulk)
			r.Get("/{id}/logs", s.deps.Admin.HostsLogs)
			r.Get("/{id}/logs.json", s.deps.Admin.HostsLogsJSON)
			r.Get("/{id}/logs/stream", s.deps.Admin.HostsLogsStream)
			r.Get("/{id}/logs/export", s.deps.Admin.HostsLogsExport)
			r.Get("/{id}/rollups.json", s.deps.Admin.HostsRollupJSON)
			r.Post("/{id}/dns/test", s.deps.Admin.HostsDNSTest)
		})
		// Built-in forward-auth portal: local access groups + members.
		r.Route("/access-groups", func(r chi.Router) {
			r.Get("/", s.deps.Admin.AccessGroupsList)
			r.Post("/", s.deps.Admin.AccessGroupsCreate)
			r.Post("/{id}/delete", s.deps.Admin.AccessGroupsDelete)
			r.Post("/{id}/members", s.deps.Admin.AccessGroupMemberAdd)
			r.Post("/{id}/members/{uid}/delete", s.deps.Admin.AccessGroupMemberRemove)
		})
		r.Get("/waf", s.deps.Admin.WafEvents)
		r.Get("/waf.json", s.deps.Admin.WafEventsJSON)
		r.Get("/waf/export", s.deps.Admin.WafEventsExport)
		r.Post("/waf/suppress", s.deps.Admin.WAFSuppressRule)
		r.Post("/waf/suppressions/{id}/delete", s.deps.Admin.WAFDeleteSuppression)
		r.Post("/waf/events/{id}/ack", s.deps.Admin.WAFAckEvent)
		r.Route("/streams", func(r chi.Router) {
			r.Get("/", s.deps.Admin.StreamsList)
			r.Post("/new", s.deps.Admin.StreamsCreate)
			r.Get("/{id}/edit", s.deps.Admin.StreamsEdit)
			r.Post("/{id}/edit", s.deps.Admin.StreamsUpdate)
			r.Post("/{id}/delete", s.deps.Admin.StreamsDelete)
		})
		r.Route("/tunnels", func(r chi.Router) {
			r.Get("/", s.deps.Admin.TunnelsList)
			r.Post("/", s.deps.Admin.TunnelsCreate)
			r.Get("/{id}", s.deps.Admin.TunnelDetail)
			r.Get("/{id}/bandwidth.json", s.deps.Admin.TunnelsBandwidthJSON)
			r.Get("/{id}/usage.csv", s.deps.Admin.TunnelsUsageCSV)
			r.Post("/{id}/revoke", s.deps.Admin.TunnelsRevoke)
			r.Post("/{id}/rotate", s.deps.Admin.TunnelsRotate)
			r.Post("/{id}/reissue", s.deps.Admin.TunnelsReissue)
			r.Post("/{id}/delete", s.deps.Admin.TunnelsDelete)
		})
		// Per-node customer-tunnel settings (enable/disable, listen
		// port, subnet, agent token rotation).
		r.Post("/nodes/{id}/tunnel/enable", s.deps.Admin.NodeTunnelEnable)
		r.Post("/nodes/{id}/tunnel/disable", s.deps.Admin.NodeTunnelDisable)
		r.Post("/nodes/{id}/tunnel/rotate", s.deps.Admin.NodeTunnelRotate)
		// Drain = move routes off + disable (non-destructive maintenance).
		r.Post("/nodes/{id}/drain", s.deps.Admin.NodesDrain)
		r.Post("/settings/customer-fields", s.deps.Admin.SettingsCustomerFields)
		r.Route("/plans", func(r chi.Router) {
			r.Get("/", s.deps.Admin.PlansList)
			r.Post("/", s.deps.Admin.PlansCreate)
			r.Post("/{id}/edit", s.deps.Admin.PlansUpdate)
			r.Post("/{id}/delete", s.deps.Admin.PlansDelete)
		})
		r.Route("/clients", func(r chi.Router) {
			r.Get("/", s.deps.Admin.ClientsList)
			r.Post("/", s.deps.Admin.ClientsCreate)
			r.Post("/{id}/edit", s.deps.Admin.ClientsUpdate)
			r.Post("/{id}/delete", s.deps.Admin.ClientsDelete)
			r.Get("/{id}", s.deps.Admin.ClientsShowDetail)
			r.Post("/{id}/status-slug/generate", s.deps.Admin.ClientsStatusSlugGenerate)
			r.Post("/{id}/status-slug/revoke", s.deps.Admin.ClientsStatusSlugRevoke)
			r.Post("/{id}/status-slug/toggle-traffic", s.deps.Admin.ClientsStatusToggleTraffic)
			r.Post("/{id}/notes", s.deps.Admin.ClientsUpdateNotes)
		})
		r.Route("/services", func(r chi.Router) {
			r.Get("/", s.deps.Admin.ServicesList)
			r.Post("/", s.deps.Admin.ServicesCreate)
			r.Post("/{id}/edit", s.deps.Admin.ServicesUpdate)
			r.Post("/{id}/delete", s.deps.Admin.ServicesDelete)
			r.Post("/{id}/suspend", s.deps.Admin.ServicesSuspend)
			r.Post("/{id}/resume", s.deps.Admin.ServicesResume)
		})
		r.Route("/users", func(r chi.Router) {
			r.Get("/", s.deps.Admin.UsersList)
			r.Post("/", s.deps.Admin.UsersCreate)
			r.Post("/{id}/edit", s.deps.Admin.UsersUpdate)
			r.Post("/{id}/scope", s.deps.Admin.UsersScopeUpdate)
			r.Post("/{id}/toggle", s.deps.Admin.UsersToggle)
			r.Post("/{id}/delete", s.deps.Admin.UsersDelete)
			r.Post("/{id}/impersonate", s.deps.Admin.UsersImpersonate)
			r.Post("/{id}/gdpr-export", s.deps.Admin.GDPRExport)
			r.Post("/{id}/gdpr-delete", s.deps.Admin.GDPRDelete)
		})
		r.Route("/api-keys", func(r chi.Router) {
			r.Get("/", s.deps.Admin.APIKeysList)
			r.Post("/", s.deps.Admin.APIKeysCreate)
			r.Post("/{id}/revoke", s.deps.Admin.APIKeysRevoke)
		})
		r.Route("/2fa", func(r chi.Router) {
			r.Get("/", s.deps.Admin.TwoFAPage)
			r.Post("/start", s.deps.Admin.TwoFAStart)
			r.Post("/confirm", s.deps.Admin.TwoFAConfirm)
			r.Post("/disable", s.deps.Admin.TwoFADisable)
			r.Post("/sms/start", s.deps.Admin.AdminSMSOTPStart)
			r.Post("/sms/confirm", s.deps.Admin.AdminSMSOTPConfirm)
			r.Post("/sms/disable", s.deps.Admin.AdminSMSOTPDisable)
			r.Post("/email/start", s.deps.Admin.AdminEmailOTPStart)
			r.Post("/email/confirm", s.deps.Admin.AdminEmailOTPConfirm)
			r.Post("/email/disable", s.deps.Admin.AdminEmailOTPDisable)
		})
		if s.deps.Passkey != nil {
			r.Route("/passkeys", func(r chi.Router) {
				r.Get("/", s.deps.Passkey.List)
				r.Post("/register/begin", s.deps.Passkey.RegisterBegin)
				r.Post("/register/finish", s.deps.Passkey.RegisterFinish)
				r.Delete("/{id}", s.deps.Passkey.Delete)
			})
		}
		r.Get("/account", s.deps.Admin.AdminAccountPage)
		r.Post("/account", s.deps.Admin.AdminAccountUpdate)
		if s.deps.OAuthIdentity != nil {
			r.Route("/oauth-identities", func(r chi.Router) {
				r.Get("/", s.deps.OAuthIdentity.List)
				r.Post("/{id}/unlink", s.deps.OAuthIdentity.Unlink)
				r.Post("/link/oidc", s.deps.OAuthIdentity.LinkOIDC)
				r.Post("/link/{provider}", s.deps.OAuthIdentity.LinkProvider)
			})
		}
		r.Get("/audit", s.deps.Admin.AuditList)
		r.Get("/audit/export", s.deps.Admin.AuditExport)
		r.Route("/saved-filters", func(r chi.Router) {
			r.Post("/{view}", s.deps.Admin.SavedFilterSave)
			r.Post("/{view}/{id}/delete", s.deps.Admin.SavedFilterDelete)
		})
		r.Get("/search", s.deps.Admin.AdminSearch)
		r.Get("/alerts", s.deps.Admin.AlertsPage)
		r.Post("/alerts/test-fire", s.deps.Admin.AlertsTestFire)
		r.Route("/backups", func(r chi.Router) {
			r.Get("/", s.deps.Admin.BackupsPage)
			r.Post("/destinations", s.deps.Admin.BackupsCreateDestination)
			r.Post("/destinations/{id}/delete", s.deps.Admin.BackupsDeleteDestination)
			r.Post("/destinations/{id}/test", s.deps.Admin.BackupsTestDestination)
			r.Post("/destinations/{id}/verify", s.deps.Admin.BackupsVerify)
			r.Post("/run-now", s.deps.Admin.BackupsRunNow)
			r.Post("/schedule", s.deps.Admin.BackupsSaveSchedule)
			r.Post("/drill/run", s.deps.Admin.DrillRunNow)
		})
		r.Route("/webhooks", func(r chi.Router) {
			r.Get("/", s.deps.Admin.WebhooksPage)
			r.Post("/", s.deps.Admin.WebhooksCreate)
			r.Post("/{id}/delete", s.deps.Admin.WebhooksDelete)
			r.Post("/{id}/test", s.deps.Admin.WebhooksTest)
		})
		r.Route("/legal", func(r chi.Router) {
			r.Get("/", s.deps.Admin.LegalDocsPage)
			r.Post("/save", s.deps.Admin.LegalDocAdmin)
		})
		r.Route("/tools", func(r chi.Router) {
			r.Get("/npm-import", s.deps.Admin.NpmImportPage)
			r.Post("/npm-import", s.deps.Admin.NpmImportSubmit)
		})
		r.Route("/ai", func(r chi.Router) {
			r.Get("/chat", s.deps.Admin.AIChatPage)
			r.Get("/chat/sessions", s.deps.Admin.AIChatListSessions)
			r.Post("/chat/sessions", s.deps.Admin.AIChatCreateSession)
			r.Get("/chat/sessions/{id}", s.deps.Admin.AIChatGetSession)
			r.Delete("/chat/sessions/{id}", s.deps.Admin.AIChatDeleteSession)
			r.Post("/chat/sessions/{id}/message", s.deps.Admin.AIChatSendMessage)
		})
		r.Route("/settings", func(r chi.Router) {
			r.Get("/", s.deps.Admin.SettingsPage)
			r.Get("/dns-providers", s.deps.Admin.DNSProvidersPage)
			r.Post("/dns-providers", s.deps.Admin.DNSProvidersCreate)
			r.Post("/dns-providers/{id}/delete", s.deps.Admin.DNSProvidersDelete)
			r.Get("/external-allowlist", s.deps.Admin.ExternalAllowlistPage)
			r.Post("/external-allowlist", s.deps.Admin.ExternalAllowlistCreate)
			r.Post("/external-allowlist/{id}/delete", s.deps.Admin.ExternalAllowlistDelete)
			r.Post("/smtp", s.deps.Admin.SettingsSMTP)
			r.Post("/acme", s.deps.Admin.SettingsACME)
			r.Post("/mtls", s.deps.Admin.SettingsMTLS)
			r.Post("/analytics", s.deps.Admin.SettingsAnalytics)
			r.Post("/geoip", s.deps.Admin.SettingsGeoIP)
			r.Post("/geoip/refresh", s.deps.Admin.SettingsGeoIPRefresh)
			r.Post("/oidc", s.deps.Admin.SettingsOIDC)
			r.Post("/oidc/test", s.deps.Admin.SettingsOIDCTestDiscovery)
			r.Post("/oauth-provider/{provider}", s.deps.Admin.SettingsOAuthProvider)
			r.Post("/turnstile", s.deps.Admin.SettingsTurnstile)
			r.Post("/cloudflare", s.deps.Admin.SettingsCloudflare)
			r.Post("/wireguard", s.deps.Admin.SettingsWireguard)
			r.Post("/sms", s.deps.Admin.SettingsSMS)
			r.Post("/sms/test", s.deps.Admin.SettingsSMSTest)
			r.Post("/sms-otp", s.deps.Admin.SettingsSMSOTPAvailable)
			r.Post("/sso-jump", s.deps.Admin.SettingsSSOJumpSave)
			r.Post("/sso-jump/rotate", s.deps.Admin.SettingsSSOJumpRotate)
			r.Post("/apidocs", s.deps.Admin.SettingsAPIDocs)
			r.Post("/require-2fa", s.deps.Admin.SettingsRequire2FA)
			r.Post("/ai", s.deps.Admin.SettingsAI)
			r.Post("/ai/test", s.deps.Admin.SettingsAITest)
			r.Get("/ai/models", s.deps.Admin.SettingsAIModels)
		})
	})

	// Client portal.
	r.Route("/app", func(r chi.Router) {
		r.Use(mw.RequireRole("client"))
		r.Get("/", s.deps.Client.Dashboard)
		r.Get("/worldmap", s.deps.Client.ClientWorldMap)
		r.Get("/services", s.deps.Client.Services)
		r.Post("/services/{id}/edit", s.deps.Client.ServiceEdit)
		r.Route("/routes", func(r chi.Router) {
			r.Get("/", s.deps.Client.RoutesList)
			r.Get("/export.csv", s.deps.Client.RouteExport)
			r.Get("/new", s.deps.Client.RouteNew)
			r.Post("/", s.deps.Client.RouteCreate)
			r.Post("/{id}/delete", s.deps.Client.RouteDelete)
			r.Post("/{id}/verify-dns", s.deps.Client.RouteVerifyDNS)
			r.Post("/{id}/retry-ssl", s.deps.Client.RouteRetrySSL)
			r.Post("/{id}/toggle-maintenance", s.deps.Client.RouteMaintenance)
			r.Get("/{id}/edit", s.deps.Client.RouteEdit)
			r.Post("/{id}/edit", s.deps.Client.RouteEditSave)
			r.Get("/{id}/logs", s.deps.Client.RouteLogs)
		})
		r.Route("/2fa", func(r chi.Router) {
			r.Get("/", s.deps.Client.TwoFAPage)
			r.Post("/start", s.deps.Client.TwoFAStart)
			r.Post("/confirm", s.deps.Client.TwoFAConfirm)
			r.Post("/disable", s.deps.Client.TwoFADisable)
			r.Post("/sms/start", s.deps.Client.SMSOTPStart)
			r.Post("/sms/confirm", s.deps.Client.SMSOTPConfirm)
			r.Post("/sms/disable", s.deps.Client.SMSOTPDisable)
			r.Post("/email/start", s.deps.Client.EmailOTPStart)
			r.Post("/email/confirm", s.deps.Client.EmailOTPConfirm)
			r.Post("/email/disable", s.deps.Client.EmailOTPDisable)
		})
		if s.deps.Passkey != nil {
			r.Route("/passkeys", func(r chi.Router) {
				r.Get("/", s.deps.Passkey.List)
				r.Post("/register/begin", s.deps.Passkey.RegisterBegin)
				r.Post("/register/finish", s.deps.Passkey.RegisterFinish)
				r.Delete("/{id}", s.deps.Passkey.Delete)
			})
		}
		r.Route("/api-keys", func(r chi.Router) {
			r.Get("/", s.deps.Client.APIKeysPage)
			r.Post("/", s.deps.Client.APIKeysCreate)
			r.Post("/{id}/revoke", s.deps.Client.APIKeysRevoke)
		})
		r.Route("/tunnels", func(r chi.Router) {
			r.Get("/", s.deps.Client.ClientTunnelsList)
			r.Post("/", s.deps.Client.ClientTunnelsCreate)
			r.Post("/{id}/revoke", s.deps.Client.ClientTunnelsRevoke)
			r.Get("/{id}/bandwidth.json", s.deps.Client.ClientTunnelsBandwidthJSON)
		})
		r.Get("/contact", s.deps.Client.ContactPage)
		r.Post("/contact", s.deps.Client.ContactSubmit)
		r.Get("/account", s.deps.Client.AccountPage)
		r.Post("/account", s.deps.Client.AccountUpdate)
		if s.deps.OAuthIdentity != nil {
			r.Route("/oauth-identities", func(r chi.Router) {
				r.Get("/", s.deps.OAuthIdentity.List)
				r.Post("/{id}/unlink", s.deps.OAuthIdentity.Unlink)
				r.Post("/link/oidc", s.deps.OAuthIdentity.LinkOIDC)
				r.Post("/link/{provider}", s.deps.OAuthIdentity.LinkProvider)
			})
		}
		r.Post("/status-page/toggle", s.deps.Client.StatusPageToggle)
		// AI chat: AdminHandlers derive a per-user tool scope from session role,
		// so clients only see their own tenant data. Rate-limited per IP.
		r.Route("/ai", func(r chi.Router) {
			r.Use(mw.RateLimit(mw.RateLimitConfig{
				RDB:         s.deps.RDB,
				PerIPPerMin: 30,
				KeyPrefix:   "hpg:rl:client-ai",
			}))
			r.Get("/chat/sessions", s.deps.Admin.AIChatListSessions)
			r.Post("/chat/sessions", s.deps.Admin.AIChatCreateSession)
			r.Get("/chat/sessions/{id}", s.deps.Admin.AIChatGetSession)
			r.Delete("/chat/sessions/{id}", s.deps.Admin.AIChatDeleteSession)
			r.Post("/chat/sessions/{id}/message", s.deps.Admin.AIChatSendMessage)
		})
	})

	// REST API v1 - bearer-token auth.
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", handlers.APIHealth)
		// Node auto-join: the join token IS the credential (in body), so
		// this MUST NOT sit behind APIKeyAuth.
		r.Post("/nodes/join", s.deps.NodeJoin.Join)
		r.Group(func(r chi.Router) {
			r.Use(mw.APIKeyAuth(s.deps.Wizard.DB))
			r.Use(mw.APIQuota(s.deps.RDB, s.deps.Wizard.DB))
			// Idempotency replay for POST provisioning calls.
			r.Use(mw.Idempotency(s.deps.Wizard.DB))
			r.Route("/services", func(r chi.Router) {
				r.Get("/", s.deps.API.ServicesList)
				r.Post("/", s.deps.API.ServiceCreate)
				r.Get("/{id}", s.deps.API.ServiceGet)
				r.Patch("/{id}", s.deps.API.ServiceUpdate)
				r.Delete("/{id}", s.deps.API.ServiceDelete)
				r.Post("/{id}/ports", s.deps.API.ServicePorts)
				r.Get("/{id}/routes", s.deps.API.ServiceRoutes)
			})
			r.Route("/routes", func(r chi.Router) {
				r.Get("/", s.deps.API.RoutesList)
				r.Post("/", s.deps.API.RouteCreate)
				r.Get("/{id}", s.deps.API.RouteGet)
				r.Patch("/{id}", s.deps.API.RouteUpdate)
				r.Delete("/{id}", s.deps.API.RouteDelete)
				r.Post("/{id}/verify-dns", s.deps.API.RouteVerifyDNS)
				r.Post("/{id}/retry-ssl", s.deps.API.RouteRetrySSL)
			})
			r.Route("/nodes", func(r chi.Router) {
				r.Get("/", s.deps.API.NodesList)
				r.Post("/", s.deps.API.NodeCreate)
				r.Get("/{id}", s.deps.API.NodeGet)
				r.Patch("/{id}", s.deps.API.NodeUpdate)
				r.Delete("/{id}", s.deps.API.NodeDelete)
				r.Post("/{id}/resync", s.deps.API.NodeResync)
			})
			r.Route("/node-pools", func(r chi.Router) {
				r.Get("/", s.deps.API.NodePoolsList)
				r.Post("/", s.deps.API.NodePoolCreate)
				r.Get("/{id}", s.deps.API.NodePoolGet)
				r.Patch("/{id}", s.deps.API.NodePoolUpdate)
				r.Delete("/{id}", s.deps.API.NodePoolDelete)
			})
			r.Route("/plans", func(r chi.Router) {
				r.Get("/", s.deps.API.PlansList)
				r.Post("/", s.deps.API.PlanCreate)
				r.Get("/{id}", s.deps.API.PlanGet)
				r.Patch("/{id}", s.deps.API.PlanUpdate)
				r.Delete("/{id}", s.deps.API.PlanDelete)
			})
			r.Route("/clients", func(r chi.Router) {
				r.Get("/", s.deps.API.ClientsList)
				r.Post("/", s.deps.API.ClientCreate)
				r.Get("/{id}", s.deps.API.ClientGet)
				r.Patch("/{id}", s.deps.API.ClientUpdate)
				r.Delete("/{id}", s.deps.API.ClientDelete)
			})
			if s.deps.FOSSBilling != nil {
				r.Route("/provisioning", func(r chi.Router) {
					r.Post("/client", s.deps.FOSSBilling.ProvisionClient)
					r.Post("/service", s.deps.FOSSBilling.ProvisionService)
					r.Post("/route", s.deps.FOSSBilling.ProvisionRoute)
					r.Put("/service/{id}/suspend", s.deps.FOSSBilling.SuspendService)
					r.Delete("/service/{id}", s.deps.FOSSBilling.DeleteService)
				})
			}
		})
	})

	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		if !s.deps.InstallState.IsInstalled() {
			http.Redirect(w, req, "/install", http.StatusSeeOther)
			return
		}
		sess := mw.SessionFromContext(req.Context())
		if sess == nil {
			http.Redirect(w, req, "/auth/login", http.StatusSeeOther)
			return
		}
		if sess.Role == "client" {
			http.Redirect(w, req, "/app", http.StatusSeeOther)
			return
		}
		http.Redirect(w, req, "/admin", http.StatusSeeOther)
	})

	// Static file server with directory-listing disabled. Prefer the embedded
	// FS (self-contained binary); fall back to disk for dev / when assets
	// aren't embedded.
	var staticHandler http.Handler
	if s.deps.StaticFS != nil {
		if sub, err := fs.Sub(s.deps.StaticFS, "web/static"); err == nil {
			staticHandler = http.FileServer(http.FS(sub))
		}
	}
	if staticHandler == nil {
		staticHandler = http.FileServer(http.Dir("web/static"))
	}
	r.Handle("/static/*", http.StripPrefix("/static/", staticCacheHeaders(noDirListing(staticHandler))))
}

// staticCacheHeaders adds a modest cache window to static assets so repeat
// page loads don't re-fetch CSS/JS on every navigation. 1h is conservative
// (assets aren't content-hashed yet); bump to immutable once filenames hash.
func staticCacheHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

// noDirListing returns 404 for any URL ending in `/`, preventing
// http.FileServer from rendering its built-in directory index.
func noDirListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || r.URL.Path == "" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func installRedirectMiddleware(state *installstate.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if state.IsInstalled() {
				next.ServeHTTP(w, r)
				return
			}
			p := r.URL.Path
			switch {
			case p == "/install",
				p == "/install/node.sh",
				p == "/healthz", p == "/readyz", p == "/metrics",
				p == "/internal/ask", p == "/internal/access-log", p == "/favicon.ico":
				next.ServeHTTP(w, r)
				return
			}
			if strings.HasPrefix(p, "/install/") || strings.HasPrefix(p, "/static/") {
				next.ServeHTTP(w, r)
				return
			}
			http.Redirect(w, r, "/install", http.StatusSeeOther)
		})
	}
}
