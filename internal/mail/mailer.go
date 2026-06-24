// Package mail wraps SMTP send with configurable host/port/auth and a
// settings-table-backed config that the admin can change at runtime.
package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	gomail "github.com/wneessen/go-mail"

	"github.com/hostyt/proxy-gateway/internal/installstate"
)

//go:embed templates/*.html.tmpl
var emailFS embed.FS

// Config is the runtime SMTP config; loaded from settings table on demand.
type Config struct {
	Host       string
	Port       int
	Encryption string // tls | ssl | none
	Username   string
	Password   string
	FromEmail  string
	FromName   string
}

// IsZero reports whether SMTP has been configured at all.
func (c Config) IsZero() bool {
	return c.Host == "" || c.FromEmail == ""
}

// Mailer renders + sends emails using settings stored in DB.
type Mailer struct {
	DB     *sql.DB
	State  *installstate.Manager
	Logger *slog.Logger

	tplOnce sync.Once
	tpl     *template.Template
	tplErr  error
}

// Send renders <name>.html.tmpl with `data` and sends to `to` with `subject`.
// Returns immediately if SMTP isn't configured (logs a warning).
func (m *Mailer) Send(ctx context.Context, to, subject, templateName string, data any) error {
	cfg, err := m.loadConfig(ctx)
	if err != nil {
		return fmt.Errorf("load smtp config: %w", err)
	}
	if cfg.IsZero() {
		m.Logger.Warn("smtp not configured; email skipped", "to", to, "subject", subject)
		return errors.New("smtp not configured")
	}

	html, text, err := m.render(templateName, data)
	if err != nil {
		return err
	}

	msg := gomail.NewMsg()
	if err := msg.FromFormat(cfg.FromName, cfg.FromEmail); err != nil {
		return err
	}
	if err := msg.To(to); err != nil {
		return err
	}
	msg.Subject(subject)
	msg.SetBodyString(gomail.TypeTextPlain, text)
	msg.AddAlternativeString(gomail.TypeTextHTML, html)

	opts := []gomail.Option{
		gomail.WithPort(cfg.Port),
		gomail.WithTimeout(15 * time.Second),
	}
	switch cfg.Encryption {
	case "ssl":
		opts = append(opts, gomail.WithSSLPort(false))
	case "tls":
		opts = append(opts, gomail.WithTLSPolicy(gomail.TLSMandatory))
	default:
		opts = append(opts, gomail.WithTLSPolicy(gomail.NoTLS))
	}
	if cfg.Username != "" {
		opts = append(opts,
			gomail.WithSMTPAuth(gomail.SMTPAuthPlain),
			gomail.WithUsername(cfg.Username),
			gomail.WithPassword(cfg.Password),
		)
	}
	opts = append(opts, gomail.WithTLSConfig(&tls.Config{
		ServerName: cfg.Host,
		MinVersion: tls.VersionTLS12,
	}))

	client, err := gomail.NewClient(cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := client.DialAndSendWithContext(sendCtx, msg); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	m.Logger.Info("email sent", "to", to, "subject", subject)
	return nil
}

// SendTest hits the SMTP server with a fixed test message.
func (m *Mailer) SendTest(ctx context.Context, to string) error {
	return m.Send(ctx, to, "Hostyt Proxy — SMTP test", "test", map[string]any{
		"AppName": "Hostyt Proxy Gateway",
	})
}

func (m *Mailer) loadConfig(ctx context.Context) (Config, error) {
	c := Config{Port: 587, Encryption: "tls", FromName: "Hostyt Proxy"}
	if m.DB == nil {
		return c, nil
	}
	rows, err := m.DB.QueryContext(ctx,
		"SELECT `key`, value, is_encrypted FROM settings WHERE `key` LIKE 'smtp.%'")
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		var enc bool
		if err := rows.Scan(&k, &v, &enc); err != nil {
			continue
		}
		if enc && m.State != nil {
			if dec, err := m.State.Decrypt(v); err == nil {
				v = dec
			} else {
				v = ""
			}
		}
		switch k {
		case "smtp.host":
			c.Host = v
		case "smtp.port":
			if n, err := strconv.Atoi(v); err == nil {
				c.Port = n
			}
		case "smtp.encryption":
			c.Encryption = v
		case "smtp.username":
			c.Username = v
		case "smtp.password":
			c.Password = v
		case "smtp.from_email":
			c.FromEmail = v
		case "smtp.from_name":
			if v != "" {
				c.FromName = v
			}
		}
	}
	// Fall back to install state if settings rows missing (post-install).
	if c.Host == "" && m.State != nil {
		if st := m.State.Get(); st.SMTP != nil {
			c.Host = st.SMTP.Host
			c.Port = st.SMTP.Port
			c.Encryption = st.SMTP.Encryption
			c.Username = st.SMTP.Username
			c.FromEmail = st.SMTP.FromEmail
			if st.SMTP.FromName != "" {
				c.FromName = st.SMTP.FromName
			}
			if st.SMTP.PasswordCipher != "" {
				if dec, err := m.State.Decrypt(st.SMTP.PasswordCipher); err == nil {
					c.Password = dec
				}
			}
		}
	}
	return c, nil
}

func (m *Mailer) render(name string, data any) (htmlBody, textBody string, err error) {
	m.tplOnce.Do(func() {
		m.tpl, m.tplErr = template.New("").ParseFS(emailFS, "templates/*.html.tmpl")
	})
	if m.tplErr != nil {
		return "", "", m.tplErr
	}
	var buf bytes.Buffer
	if err := m.tpl.ExecuteTemplate(&buf, name+".html.tmpl", data); err != nil {
		return "", "", err
	}
	html := buf.String()
	return html, htmlToText(html), nil
}

// htmlToText is a cheap text fallback — strips tags, collapses whitespace.
// Good enough for transactional emails; users with HTML clients see the real thing.
func htmlToText(s string) string {
	var out strings.Builder
	skip := false
	for _, r := range s {
		switch {
		case r == '<':
			skip = true
		case r == '>':
			skip = false
		case skip:
		default:
			out.WriteRune(r)
		}
	}
	lines := strings.Split(out.String(), "\n")
	cleaned := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			cleaned = append(cleaned, l)
		}
	}
	return strings.Join(cleaned, "\n")
}
