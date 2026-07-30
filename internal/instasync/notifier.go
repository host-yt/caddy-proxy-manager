// Package instasync sends sync triggers to registered slave HPG instances.
package instasync

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
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
		// Slave URLs are admin-supplied; block private/loopback/metadata dials
		// and non-http(s) redirects (defense in depth beyond SlaveAdd's save-time check).
		client: security.SafeHTTPClient(10 * time.Second),
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

	var wg sync.WaitGroup
	for _, s := range slaves {
		s := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			n.pushSlave(ctx, s)
		}()
	}
	wg.Wait()
}

func (n *Notifier) pushSlave(ctx context.Context, s slave) {
	pushURL := strings.TrimRight(s.url, "/") + "/internal/sync/push"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pushURL, nil)
	if err != nil {
		n.updateStatus(ctx, s.id, "error", err.Error())
		return
	}
	// Re-validate at dial time: catches rows saved before this gate existed
	// or written directly to the DB, not just ones created via SlaveAdd.
	if verr := security.ValidateOutboundURL(req.URL); verr != nil || req.URL.Scheme != "https" {
		n.Logger.Warn("sync push blocked: unsafe slave url", "slave", s.name)
		n.updateStatus(ctx, s.id, "error", "url rejected: unsafe host or scheme")
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
