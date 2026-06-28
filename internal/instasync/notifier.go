// Package instasync sends sync triggers to registered slave HPG instances.
package instasync

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
)

// Notifier pushes sync triggers to registered slave HPG instances.
// Nil-safe: Notify is a no-op when the receiver is nil.
type Notifier struct {
	DB     func() *sql.DB
	State  *installstate.Manager
	Logger *slog.Logger
	client *http.Client
}

// New creates a Notifier wired to the given DB and state manager.
func New(db func() *sql.DB, state *installstate.Manager, logger *slog.Logger) *Notifier {
	return &Notifier{
		DB:     db,
		State:  state,
		Logger: logger,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Notify fires sync triggers to all registered slaves in a background goroutine.
func (n *Notifier) Notify(ctx context.Context) {
	if n == nil || n.DB == nil {
		return
	}
	go func() {
		bctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		n.notify(bctx)
	}()
}

type slave struct {
	id    int
	name  string
	url   string
	token string
}

func (n *Notifier) notify(ctx context.Context) {
	db := n.DB()
	if db == nil {
		return
	}
	rows, err := db.QueryContext(ctx, "SELECT id, name, url, token_enc FROM sync_slaves ORDER BY id")
	if err != nil {
		n.Logger.Warn("sync notifier: list slaves", "err", err)
		return
	}
	var slaves []slave
	for rows.Next() {
		var s slave
		var tokenEnc string
		if err := rows.Scan(&s.id, &s.name, &s.url, &tokenEnc); err != nil {
			continue
		}
		tok, err := n.State.Decrypt(tokenEnc)
		if err != nil {
			n.Logger.Warn("sync notifier: decrypt token", "slave", s.name, "err", err)
			continue
		}
		s.token = tok
		slaves = append(slaves, s)
	}
	rows.Close()

	for _, s := range slaves {
		s := s
		go n.pushSlave(ctx, s)
	}
}

func (n *Notifier) pushSlave(ctx context.Context, s slave) {
	url := strings.TrimRight(s.url, "/") + "/internal/sync/push"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		n.updateStatus(ctx, s.id, "error", err.Error())
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := n.client.Do(req)
	if err != nil {
		n.Logger.Warn("sync push failed", "slave", s.name, "err", err)
		n.updateStatus(ctx, s.id, "error", err.Error())
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		n.Logger.Info("sync push ok", "slave", s.name)
		n.updateStatus(ctx, s.id, "ok", "")
	} else {
		msg := "HTTP " + resp.Status
		n.Logger.Warn("sync push non-2xx", "slave", s.name, "status", resp.StatusCode)
		n.updateStatus(ctx, s.id, "error", msg)
	}
}

func (n *Notifier) updateStatus(ctx context.Context, id int, status, errMsg string) {
	db := n.DB()
	if db == nil {
		return
	}
	var errCol interface{} = nil
	if errMsg != "" {
		errCol = errMsg
	}
	_, _ = db.ExecContext(ctx,
		"UPDATE sync_slaves SET last_sync_at=NOW(), last_sync_status=?, last_sync_error=? WHERE id=?",
		status, errCol, id)
}
