package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

// pskTokenTTLMinutes bounds how long the operator has to run the rekey
// script on the node, matching the join-token TTL.
const pskTokenTTLMinutes = 30

// nodePSKView is the mesh-PSK state of one node as the detail page shows it.
type nodePSKView struct {
	Active   bool
	Pending  bool
	Token    string // plaintext, only while the rekey token is unexpired
	PanelURL string
}

// loadNodePSK reads the PSK state for the node detail page. Errors degrade to
// "no PSK" - this is a status panel, not an authorization decision.
func (h *AdminHandlers) loadNodePSK(ctx context.Context, db *sql.DB, id int64) nodePSKView {
	v := nodePSKView{PanelURL: strings.TrimRight(appURLFromInstallState(h.State), "/")}
	var active, pending, tokenLive sql.NullInt64
	var tokenEnc sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT wg_psk_enc IS NOT NULL, wg_psk_pending_enc IS NOT NULL, wg_psk_token_enc,
		        wg_psk_token_expires > `+store.Now()+`
		 FROM caddy_nodes WHERE id = ?`, id,
	).Scan(&active, &pending, &tokenEnc, &tokenLive); err != nil {
		return v
	}
	v.Active, v.Pending = active.Int64 != 0, pending.Int64 != 0
	if tokenLive.Valid && tokenLive.Int64 != 0 && tokenEnc.Valid && h.State != nil {
		if tok, err := h.State.Scoped("wg").Decrypt(tokenEnc.String); err == nil {
			v.Token = tok
		}
	}
	return v
}

// NodesPSKEnable handles POST /admin/nodes/{id}/psk/enable and .../psk/rotate.
// Both stage a new key: the currently active one keeps the mesh up until the
// node confirms it installed the replacement (see NodePSKHandler.Confirm).
func (h *AdminHandlers) NodesPSKEnable(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	dest := fmt.Sprintf("/admin/nodes/%d", id)
	if db == nil || h.State == nil || id == 0 {
		redirectWithFlash(w, r, dest, "", "PSK rekey unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	enc := h.State.Scoped("wg")
	psk, err := wireguard.GeneratePresharedKey()
	if err != nil {
		redirectWithFlash(w, r, dest, "", "key generation failed")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		redirectWithFlash(w, r, dest, "", "token generation failed")
		return
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	pskEnc, err := enc.Encrypt(psk)
	if err != nil {
		redirectWithFlash(w, r, dest, "", "encrypt failed")
		return
	}
	tokenEnc, err := enc.Encrypt(token)
	if err != nil {
		redirectWithFlash(w, r, dest, "", "encrypt failed")
		return
	}

	var hadActive sql.NullInt64
	_ = db.QueryRowContext(ctx, "SELECT wg_psk_enc IS NOT NULL FROM caddy_nodes WHERE id = ?", id).Scan(&hadActive)

	// Expiry is computed DB-side so it shares a clock with the
	// 'wg_psk_token_expires > NOW()' checks on the public endpoints.
	if _, err := db.ExecContext(ctx,
		`UPDATE caddy_nodes SET wg_psk_pending_enc = ?, wg_psk_token_hash = ?, wg_psk_token_enc = ?,
		   wg_psk_token_expires = `+store.DateAddMinutes(pskTokenTTLMinutes)+`
		 WHERE id = ?`,
		pskEnc, hex.EncodeToString(sum[:]), tokenEnc, id); err != nil {
		h.Logger.Error("node psk stage", "node_id", id, "err", err)
		redirectWithFlash(w, r, dest, "", "db update failed")
		return
	}

	action := "node.psk.enable"
	if hadActive.Int64 != 0 {
		action = "node.psk.rotate"
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: action, Entity: "node", EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, dest,
		fmt.Sprintf("New mesh PSK staged. Run the command below on the node within %d minutes; the current key stays active until the node confirms.", pskTokenTTLMinutes),
		"")
}

// NodesPSKClear drops the PSK on the panel side. Emergency exit only: the
// node keeps its own PresharedKey line, so the mesh stays down until the
// operator removes it there too (the flash spells out the command).
func (h *AdminHandlers) NodesPSKClear(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	dest := fmt.Sprintf("/admin/nodes/%d", id)
	if db == nil || id == 0 {
		redirectWithFlash(w, r, dest, "", "PSK clear unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx,
		`UPDATE caddy_nodes SET wg_psk_enc = NULL, wg_psk_pending_enc = NULL, wg_psk_token_hash = NULL,
		   wg_psk_token_enc = NULL, wg_psk_token_expires = NULL WHERE id = ?`, id); err != nil {
		redirectWithFlash(w, r, dest, "", "db update failed")
		return
	}
	if h.WriteWGConfig != nil {
		_ = h.WriteWGConfig(ctx)
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "node.psk.clear", Entity: "node", EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, dest,
		"Mesh PSK cleared on the panel. The node still has it - run: sed -i '/^PresharedKey/d' /etc/wireguard/wg0.conf && wg syncconf wg0 <(wg-quick strip wg0)",
		"")
}
