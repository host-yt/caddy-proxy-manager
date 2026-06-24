package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hostyt/proxy-gateway/internal/auth"
	"github.com/hostyt/proxy-gateway/internal/httpserver/middleware"
	"github.com/hostyt/proxy-gateway/internal/installstate"
	"github.com/hostyt/proxy-gateway/internal/store"
	"github.com/hostyt/proxy-gateway/internal/view"
)

// Wizard owns the install flow. Single instance per app.
type Wizard struct {
	State      *installstate.Manager
	Templates  *view.InstallTemplates
	Logger     *slog.Logger
	Migrations embed.FS
	MigDir     string

	// ResyncNode (optional) is invoked after CaddySubmit successfully
	// inserts a node. The wizard itself does not own routing logic; this
	// hook lets the wired routes.Service push the panel's self-bootstrap
	// route to the brand-new node so the operator can reach the panel via
	// their public domain immediately, without manually adding a host.
	ResyncNode func(ctx context.Context, nodeID int64) error

	mu sync.Mutex
	db *sql.DB // opened after DB step
}

// DB returns the live pool once the wizard has connected. Nil before that.
func (w *Wizard) DB() *sql.DB {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.db
}

// Connect (re)opens the DB pool using a saved DBState + decrypted password.
// Used at boot if state already has DB credentials.
func (w *Wizard) Connect(ctx context.Context) error {
	s := w.State.Get()
	if s.DB == nil {
		return errors.New("no DB credentials saved")
	}
	password, err := w.State.Decrypt(s.DB.PasswordCipher)
	if err != nil {
		return err
	}
	dsn := installstate.BuildDSN(*s.DB, password)
	db, err := store.Open(ctx, dsn, 15*time.Second)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.db = db
	w.mu.Unlock()
	return nil
}

// --- View payloads --------------------------------------------------------

type wizardView struct {
	Steps     []string
	Completed map[string]bool
	Form      any
	Error     string
	CSPNonce  string
}

func (v wizardView) IsDone(step string) bool { return v.Completed[step] }

// wizardCtxNonce extracts the CSP nonce; wizard's view() has no *http.Request
// so we stash it via a thread-local using request-scoped state. The Index
// handler passes it explicitly through r - see view(step, form, errMsg, r).
//
// view kept variadic to avoid touching every call site at once.
func (w *Wizard) view(step string, form any, errMsg string) wizardView {
	s := w.State.Get()
	done := map[string]bool{}
	for _, st := range installstate.StepOrder {
		if st == step {
			break
		}
		done[st] = true
	}
	if s.Installed {
		for _, st := range installstate.StepOrder {
			done[st] = true
		}
	}
	return wizardView{
		Steps:     installstate.StepOrder,
		Completed: done,
		Form:      form,
		Error:     errMsg,
	}
}

// renderR is like render but also injects the per-request CSP nonce into v.
func (w *Wizard) renderR(rw http.ResponseWriter, r *http.Request, step string, v wizardView) {
	v.CSPNonce = middleware.CSPNonce(r.Context())
	w.render(rw, step, v)
}

func (w *Wizard) render(rw http.ResponseWriter, step string, v wizardView) {
	var buf bytes.Buffer
	if err := w.Templates.Render(&buf, step, v); err != nil {
		w.Logger.Error("wizard render", "step", step, "err", err)
		http.Error(rw, "render failed", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(buf.Bytes())
}

func (w *Wizard) redirectTo(rw http.ResponseWriter, r *http.Request, step string) {
	http.Redirect(rw, r, "/install?step="+step, http.StatusSeeOther)
}

// --- GET /install ---------------------------------------------------------

func (w *Wizard) Index(rw http.ResponseWriter, r *http.Request) {
	s := w.State.Get()
	step := r.URL.Query().Get("step")
	if step == "" {
		step = s.CurrentStep
	}
	if step == "" {
		step = installstate.StepWelcome
	}
	// Wizard locks itself once installed. Done page stays reachable so the
	// "Install complete" screen renders right after the Caddy step.
	if w.State.IsInstalled() && step != installstate.StepDone {
		http.Redirect(rw, r, "/auth/login", http.StatusSeeOther)
		return
	}

	switch step {
	case installstate.StepWelcome:
		w.renderR(rw, r, step, w.view(step, struct{}{}, ""))
	case installstate.StepDB:
		f := dbForm{Host: "mariadb", Port: 3306, Name: "hostyt_proxy", User: "hostyt"}
		if s.DB != nil {
			f = dbForm{Host: s.DB.Host, Port: s.DB.Port, Name: s.DB.Name, User: s.DB.User, TLS: s.DB.TLS}
		}
		w.renderR(rw, r, step, w.view(step, f, ""))
	case installstate.StepAdmin:
		f := adminForm{}
		if s.Admin != nil {
			f.Email, f.FullName = s.Admin.Email, s.Admin.FullName
		}
		w.renderR(rw, r, step, w.view(step, f, ""))
	case installstate.StepApp:
		f := appForm{}
		if s.App != nil {
			f.URL = s.App.URL
		}
		w.renderR(rw, r, step, w.view(step, f, ""))
	case installstate.StepSMTP:
		f := smtpForm{Port: 587, Encryption: "tls"}
		if s.SMTP != nil {
			f = smtpForm{
				Host: s.SMTP.Host, Port: s.SMTP.Port, Encryption: s.SMTP.Encryption,
				Username: s.SMTP.Username, FromEmail: s.SMTP.FromEmail, FromName: s.SMTP.FromName,
			}
		}
		w.renderR(rw, r, step, w.view(step, f, ""))
	case installstate.StepCaddy:
		f := caddyForm{Name: "node-1", APIURL: "http://caddy:2019"}
		if s.CaddyNode != nil {
			f = caddyForm{
				Name: s.CaddyNode.Name, APIURL: s.CaddyNode.APIURL,
				PublicHostname: s.CaddyNode.PublicHostname, PublicIP: s.CaddyNode.PublicIP,
			}
		}
		w.renderR(rw, r, step, w.view(step, f, ""))
	case installstate.StepDone:
		// Pass the configured public APP URL to the done view so the
		// operator can jump straight to the panel domain (which is
		// already wired into the new Caddy node via the self-bootstrap
		// route added by CaddySubmit).
		appURL := ""
		if s.App != nil {
			appURL = strings.TrimRight(s.App.URL, "/")
		}
		w.renderR(rw, r, step, w.view(step, struct{ AppURL string }{AppURL: appURL}, ""))
	default:
		http.NotFound(rw, r)
	}
}

// --- POST /install/start --------------------------------------------------

func (w *Wizard) Start(rw http.ResponseWriter, r *http.Request) {
	// If operator pasted the install token in the welcome form, persist it
	// as a cookie for the rest of the wizard so they don't need to re-paste
	// it on every step. The InstallGuard middleware reads X-Install-Token
	// / form / query / cookie in that order.
	_ = r.ParseForm()
	if tok := strings.TrimSpace(r.FormValue("install_token")); tok != "" {
		// Secure=true whenever we know the connection is TLS. Behind a
		// reverse proxy we look at X-Forwarded-Proto (matches the pattern
		// used by SecurityHeaders middleware). The cookie is HttpOnly +
		// SameSite=Strict so it cannot be read by JS and is not sent on
		// cross-site navigations - but missing Secure under plain HTTP
		// would still expose it to a MITM on a misconfigured deploy.
		secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
		http.SetCookie(rw, &http.Cookie{
			Name:     "hpg_install_token",
			Value:    tok,
			Path:     "/install",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   60 * 60, // 1h, plenty for one walkthrough
		})
	}
	s := w.State.Get()
	s.CurrentStep = installstate.StepDB
	_ = w.State.Save(&s)
	w.redirectTo(rw, r, installstate.StepDB)
}

// --- POST /install/db -----------------------------------------------------

type dbForm struct {
	Host     string
	Port     int
	Name     string
	User     string
	Password string
	TLS      bool
}

func (w *Wizard) DBSubmit(rw http.ResponseWriter, r *http.Request) {
	if w.State.IsInstalled() { // wizard locked: never repoint the live DB
		http.NotFound(rw, r)
		return
	}
	_ = r.ParseForm()
	port, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	form := dbForm{
		Host:     strings.TrimSpace(r.FormValue("host")),
		Port:     port,
		Name:     strings.TrimSpace(r.FormValue("name")),
		User:     strings.TrimSpace(r.FormValue("user")),
		Password: r.FormValue("password"),
		TLS:      r.FormValue("tls") == "1",
	}
	if form.Host == "" || form.Port == 0 || form.Name == "" || form.User == "" || form.Password == "" {
		w.renderR(rw, r, installstate.StepDB, w.view(installstate.StepDB, form, "All fields are required."))
		return
	}

	dbState := installstate.DBState{
		Host: form.Host, Port: form.Port, Name: form.Name,
		User: form.User, TLS: form.TLS,
	}
	dsn := installstate.BuildDSN(dbState, form.Password)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := store.Ping(ctx, dsn); err != nil {
		w.Logger.Warn("install: db ping failed", "host", form.Host, "err", err)
		w.renderR(rw, r, installstate.StepDB, w.view(installstate.StepDB, form, "Connection failed: "+sanitizeErr(err)))
		return
	}

	pwCipher, err := w.State.Encrypt(form.Password)
	if err != nil {
		w.renderR(rw, r, installstate.StepDB, w.view(installstate.StepDB, form, "Internal error encrypting password."))
		return
	}
	dbState.PasswordCipher = pwCipher

	// Open pool + run migrations.
	pool, err := store.Open(ctx, dsn, 10*time.Second)
	if err != nil {
		w.renderR(rw, r, installstate.StepDB, w.view(installstate.StepDB, form, "Pool open failed: "+sanitizeErr(err)))
		return
	}
	if err := store.RunMigrations(ctx, pool, w.Migrations, w.MigDir); err != nil {
		_ = pool.Close()
		w.Logger.Error("install: migrations failed", "err", err)
		w.renderR(rw, r, installstate.StepDB, w.view(installstate.StepDB, form, "Migrations failed: "+sanitizeErr(err)))
		return
	}

	w.mu.Lock()
	if w.db != nil {
		_ = w.db.Close()
	}
	w.db = pool
	w.mu.Unlock()

	s := w.State.Get()
	s.DB = &dbState

	// DR/migration: if the target DB already holds a finished installation
	// (>=1 admin), hydrate state from it instead of forcing wizard re-entry.
	// Encrypted columns stay readable only when APP_SECRET matches the one
	// the prior install used; we don't decrypt here, just mirror plaintext.
	if hydrated, herr := w.hydrateFromExistingDB(ctx, pool, &s); herr != nil {
		w.Logger.Warn("install: existing-install detect failed", "err", herr)
	} else if hydrated {
		s.Installed = true
		s.CurrentStep = installstate.StepDone
		if err := w.State.Save(&s); err != nil {
			w.renderR(rw, r, installstate.StepDB, w.view(installstate.StepDB, form, "Save failed."))
			return
		}
		w.clearInstallTokenCookie(rw, r)
		w.Logger.Info("install: existing installation detected, wizard skipped",
			"admin_email", maskEmail(s.Admin.Email))
		http.Redirect(rw, r, "/auth/login?recovered=1", http.StatusSeeOther)
		return
	}

	s.CurrentStep = installstate.StepAdmin
	if err := w.State.Save(&s); err != nil {
		w.renderR(rw, r, installstate.StepDB, w.view(installstate.StepDB, form, "Save failed."))
		return
	}
	w.redirectTo(rw, r, installstate.StepAdmin)
}

// hydrateFromExistingDB checks if the connected DB already has at least one
// admin and, if so, mirrors enough of the persisted config back into the
// install state so the wizard can lock itself and the panel boots ready.
// Returns true when an existing install was detected and state was populated.
func (w *Wizard) hydrateFromExistingDB(ctx context.Context, db *sql.DB, s *installstate.State) (bool, error) {
	var admin installstate.AdminState
	err := db.QueryRowContext(ctx,
		"SELECT id, email, COALESCE(full_name,'') FROM users "+
			"WHERE role IN ('admin','super_admin') AND is_active = 1 "+
			"ORDER BY id LIMIT 1",
	).Scan(&admin.UserID, &admin.Email, &admin.FullName)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	s.Admin = &admin

	// Pull plaintext settings (app URL, SMTP host/port/from). Encrypted
	// values (passwords) stay in DB; runtime decrypts via APP_SECRET on demand.
	rows, err := db.QueryContext(ctx,
		"SELECT `key`, value FROM settings WHERE `key` IN ("+
			"'app.url','smtp.host','smtp.port','smtp.encryption',"+
			"'smtp.username','smtp.from_email','smtp.from_name')")
	if err == nil {
		defer rows.Close()
		smtp := installstate.SMTPState{}
		var haveSMTP bool
		for rows.Next() {
			var k, v string
			if rows.Scan(&k, &v) != nil {
				continue
			}
			switch k {
			case "app.url":
				if v != "" {
					s.App = &installstate.AppState{URL: v}
				}
			case "smtp.host":
				smtp.Host = v
				haveSMTP = true
			case "smtp.port":
				p, _ := strconv.Atoi(v)
				smtp.Port = p
			case "smtp.encryption":
				smtp.Encryption = v
			case "smtp.username":
				smtp.Username = v
			case "smtp.from_email":
				smtp.FromEmail = v
			case "smtp.from_name":
				smtp.FromName = v
			}
		}
		if haveSMTP {
			s.SMTP = &smtp
		}
	}

	// First caddy node, if any, fills the install state's node slot so the
	// "done" screen + later resync logic have something to reference.
	var node installstate.NodeState
	nerr := db.QueryRowContext(ctx,
		"SELECT name, api_url, COALESCE(public_hostname,''), COALESCE(public_ip,'') "+
			"FROM caddy_nodes ORDER BY id LIMIT 1",
	).Scan(&node.Name, &node.APIURL, &node.PublicHostname, &node.PublicIP)
	if nerr == nil {
		s.CaddyNode = &node
	}
	return true, nil
}

// --- POST /install/admin --------------------------------------------------

type adminForm struct {
	FullName string
	Email    string
}

func (w *Wizard) AdminSubmit(rw http.ResponseWriter, r *http.Request) {
	if w.State.IsInstalled() { // wizard locked: never mint a second super_admin
		http.NotFound(rw, r)
		return
	}
	if w.DB() == nil {
		w.redirectTo(rw, r, installstate.StepDB)
		return
	}
	_ = r.ParseForm()
	form := adminForm{
		FullName: strings.TrimSpace(r.FormValue("full_name")),
		Email:    strings.ToLower(strings.TrimSpace(r.FormValue("email"))),
	}
	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")
	if form.FullName == "" || form.Email == "" || password == "" {
		w.renderR(rw, r, installstate.StepAdmin, w.view(installstate.StepAdmin, form, "All fields are required."))
		return
	}
	if len(password) < 12 {
		w.renderR(rw, r, installstate.StepAdmin, w.view(installstate.StepAdmin, form, "Password must be at least 12 characters."))
		return
	}
	if password != confirm {
		w.renderR(rw, r, installstate.StepAdmin, w.view(installstate.StepAdmin, form, "Passwords don't match."))
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		w.renderR(rw, r, installstate.StepAdmin, w.view(installstate.StepAdmin, form, "Internal error hashing password."))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res, err := w.DB().ExecContext(ctx,
		"INSERT INTO users (email, password_hash, role, full_name, is_active) VALUES (?, ?, 'super_admin', ?, 1)",
		form.Email, hash, form.FullName,
	)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			w.renderR(rw, r, installstate.StepAdmin, w.view(installstate.StepAdmin, form, "Email already exists."))
			return
		}
		w.Logger.Error("install: insert admin", "err", err)
		w.renderR(rw, r, installstate.StepAdmin, w.view(installstate.StepAdmin, form, "DB insert failed: "+sanitizeErr(err)))
		return
	}
	id, _ := res.LastInsertId()

	s := w.State.Get()
	s.Admin = &installstate.AdminState{UserID: id, Email: form.Email, FullName: form.FullName}
	s.CurrentStep = installstate.StepApp
	_ = w.State.Save(&s)
	w.redirectTo(rw, r, installstate.StepApp)
}

// --- POST /install/app ----------------------------------------------------

type appForm struct {
	URL string
}

func (w *Wizard) AppSubmit(rw http.ResponseWriter, r *http.Request) {
	if w.State.IsInstalled() { // wizard locked: defense-in-depth with install_guard
		http.NotFound(rw, r)
		return
	}
	_ = r.ParseForm()
	form := appForm{URL: strings.TrimSpace(r.FormValue("url"))}
	if form.URL == "" {
		w.renderR(rw, r, installstate.StepApp, w.view(installstate.StepApp, form, "URL required."))
		return
	}
	u, err := url.Parse(form.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		w.renderR(rw, r, installstate.StepApp, w.view(installstate.StepApp, form, "Invalid URL - must include http:// or https:// and a host."))
		return
	}
	s := w.State.Get()
	s.App = &installstate.AppState{URL: form.URL}
	s.CurrentStep = installstate.StepSMTP
	_ = w.State.Save(&s)
	w.redirectTo(rw, r, installstate.StepSMTP)
}

// --- POST /install/smtp ---------------------------------------------------

type smtpForm struct {
	Host       string
	Port       int
	Encryption string
	Username   string
	FromEmail  string
	FromName   string
}

func (w *Wizard) SMTPSubmit(rw http.ResponseWriter, r *http.Request) {
	if w.State.IsInstalled() { // wizard locked: defense-in-depth with install_guard
		http.NotFound(rw, r)
		return
	}
	_ = r.ParseForm()
	if r.FormValue("skip") == "1" {
		s := w.State.Get()
		s.CurrentStep = installstate.StepCaddy
		_ = w.State.Save(&s)
		w.redirectTo(rw, r, installstate.StepCaddy)
		return
	}
	port, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	form := smtpForm{
		Host:       strings.TrimSpace(r.FormValue("host")),
		Port:       port,
		Encryption: r.FormValue("encryption"),
		Username:   strings.TrimSpace(r.FormValue("username")),
		FromEmail:  strings.TrimSpace(r.FormValue("from_email")),
		FromName:   strings.TrimSpace(r.FormValue("from_name")),
	}
	password := r.FormValue("password")

	if form.Host == "" || form.Port == 0 || form.FromEmail == "" {
		w.renderR(rw, r, installstate.StepSMTP, w.view(installstate.StepSMTP, form, "Host, port, and from email are required (or click Skip)."))
		return
	}

	smtp := installstate.SMTPState{
		Host: form.Host, Port: form.Port, Encryption: form.Encryption,
		Username: form.Username, FromEmail: form.FromEmail, FromName: form.FromName,
	}
	if password != "" {
		c, err := w.State.Encrypt(password)
		if err != nil {
			w.renderR(rw, r, installstate.StepSMTP, w.view(installstate.StepSMTP, form, "Internal error."))
			return
		}
		smtp.PasswordCipher = c
	}

	s := w.State.Get()
	s.SMTP = &smtp
	s.CurrentStep = installstate.StepCaddy
	_ = w.State.Save(&s)
	w.redirectTo(rw, r, installstate.StepCaddy)
}

// clearInstallTokenCookie expires the wizard's install-token cookie once
// the wizard locks itself. Without this, a stolen cookie value remains
// valid for state-changing posts to /install/* should the operator ever
// re-open the wizard before the cookie's 1-hour TTL.
func (w *Wizard) clearInstallTokenCookie(rw http.ResponseWriter, r *http.Request) {
	http.SetCookie(rw, &http.Cookie{
		Name:     "hpg_install_token",
		Value:    "",
		Path:     "/install",
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// --- POST /install/caddy --------------------------------------------------

type caddyForm struct {
	Name           string
	APIURL         string
	PublicHostname string
	PublicIP       string
}

func (w *Wizard) CaddySubmit(rw http.ResponseWriter, r *http.Request) {
	if w.State.IsInstalled() { // wizard locked: never register a rogue node
		http.NotFound(rw, r)
		return
	}
	if w.DB() == nil {
		w.redirectTo(rw, r, installstate.StepDB)
		return
	}
	_ = r.ParseForm()
	form := caddyForm{
		Name:           strings.TrimSpace(r.FormValue("name")),
		APIURL:         strings.TrimSpace(r.FormValue("api_url")),
		PublicHostname: strings.TrimSpace(r.FormValue("public_hostname")),
		PublicIP:       strings.TrimSpace(r.FormValue("public_ip")),
	}
	if form.Name == "" || form.APIURL == "" || form.PublicHostname == "" {
		w.renderR(rw, r, installstate.StepCaddy, w.view(installstate.StepCaddy, form, "Name, API URL, and public hostname are required."))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Ensure a default node_group exists, then insert the node.
	var groupID int64
	err := w.DB().QueryRowContext(ctx, "SELECT id FROM node_groups WHERE name = 'default' LIMIT 1").Scan(&groupID)
	if errors.Is(err, sql.ErrNoRows) {
		res, ierr := w.DB().ExecContext(ctx, "INSERT INTO node_groups (name, mode) VALUES ('default', 'single')")
		if ierr != nil {
			w.renderR(rw, r, installstate.StepCaddy, w.view(installstate.StepCaddy, form, "Insert group failed: "+sanitizeErr(ierr)))
			return
		}
		groupID, _ = res.LastInsertId()
	} else if err != nil {
		w.renderR(rw, r, installstate.StepCaddy, w.view(installstate.StepCaddy, form, "DB query failed: "+sanitizeErr(err)))
		return
	}

	// approved_at = NOW(): operator entered node manually in wizard, so trust it
	// (vs auto-join flow which leaves approved_at NULL until explicit Approve).
	res, err := w.DB().ExecContext(ctx,
		`INSERT INTO caddy_nodes (name, api_url, public_hostname, public_ip, node_group_id, max_routes, is_enabled, health_status, approved_at)
		 VALUES (?, ?, ?, ?, ?, 1000, 1, 'unknown', NOW())`,
		form.Name, form.APIURL, form.PublicHostname, form.PublicIP, groupID,
	)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			w.renderR(rw, r, installstate.StepCaddy, w.view(installstate.StepCaddy, form, "Node name already exists."))
			return
		}
		w.renderR(rw, r, installstate.StepCaddy, w.view(installstate.StepCaddy, form, "Insert node failed: "+sanitizeErr(err)))
		return
	}
	newNodeID, _ := res.LastInsertId()

	// Self-bootstrap: push the panel route to the brand-new node so the
	// operator can hit https://<panel-domain> immediately. Best-effort -
	// a transient Caddy issue here must not block wizard completion; the
	// drift reconciler will catch up within a few minutes.
	if w.ResyncNode != nil && newNodeID > 0 {
		pushCtx, pushCancel := context.WithTimeout(r.Context(), 10*time.Second)
		if perr := w.ResyncNode(pushCtx, newNodeID); perr != nil {
			w.Logger.Warn("wizard: initial caddy push failed (will retry via drift reconciler)",
				"node_id", newNodeID, "err", perr)
		}
		pushCancel()
	}

	s := w.State.Get()
	s.CaddyNode = &installstate.NodeState{
		Name: form.Name, APIURL: form.APIURL,
		PublicHostname: form.PublicHostname, PublicIP: form.PublicIP,
	}
	s.Installed = true
	s.CurrentStep = installstate.StepDone
	_ = w.State.Save(&s)
	w.clearInstallTokenCookie(rw, r)
	w.Logger.Info("install: complete", "admin_email", maskEmail(s.Admin.Email))
	w.redirectTo(rw, r, installstate.StepDone)
}

// --- helpers --------------------------------------------------------------

// sanitizeErr strips potentially sensitive bits before showing to user.
func sanitizeErr(err error) string {
	msg := err.Error()
	// Strip password from any DSN-style strings.
	if i := strings.Index(msg, "@tcp"); i > 0 {
		// keep only "@tcp(...)..." part
		if j := strings.LastIndex(msg[:i], ":"); j > 0 {
			msg = "<user>:<redacted>" + msg[i:]
		}
	}
	if len(msg) > 240 {
		msg = msg[:240] + "..."
	}
	return msg
}

func maskEmail(email string) string {
	at := strings.IndexByte(email, '@')
	if at <= 1 {
		return "***"
	}
	return string(email[0]) + "***" + email[at:]
}
