// Package notify glues the routes service to mail.Mailer + sms.Sender
// so route-lifecycle transitions can reach the owning client out of band.
// Both transports are nil-safe; unconfigured ones are skipped silently.
package notify

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/hostyt/proxy-gateway/internal/mail"
	"github.com/hostyt/proxy-gateway/internal/sms"
)

// Customer notifies the operator's end customers. Implements the
// routes.CustomerNotifier interface.
type Customer struct {
	DB     func() *sql.DB
	Mail   *mail.Mailer
	SMS    *sms.Sender
	Logger *slog.Logger
}

// Notify resolves a client's email + phone and fans the message out.
// Failures are logged but never returned — notifications must not block
// or fail the calling lifecycle event (auto-failover, etc.).
func (c *Customer) Notify(ctx context.Context, clientID int64, subject, body string) {
	if c.DB == nil {
		return
	}
	db := c.DB()
	if db == nil {
		return
	}
	var email string
	var phone sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT u.email, u.phone_e164
		   FROM clients cl JOIN users u ON u.id = cl.user_id WHERE cl.id = ?`,
		clientID).Scan(&email, &phone); err != nil {
		c.Logger.Debug("notify: client lookup", "client_id", clientID, "err", err)
		return
	}
	if email != "" && c.Mail != nil {
		if err := c.Mail.Send(ctx, email, subject, "notice", map[string]any{
			"Subject": subject,
			"Body":    body,
		}); err != nil {
			c.Logger.Warn("notify: email send", "to", email, "err", err)
		}
	}
	if phone.Valid && phone.String != "" && c.SMS != nil {
		// SMS gets a stripped-down body — keep under 160 chars total.
		short := subject
		if len(short) > 140 {
			short = short[:140]
		}
		if err := c.SMS.Send(ctx, phone.String, short); err != nil {
			c.Logger.Debug("notify: sms send", "to", phone.String, "err", err)
		}
	}
}
