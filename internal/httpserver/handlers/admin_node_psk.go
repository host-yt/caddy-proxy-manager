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
	// The token outlives the confirm on purpose (retryable confirm), so gate
	// the command on a key still being staged - otherwise the page keeps
	// offering a rekey command for a rekey that already finished.
	if v.Pending && tokenLive.Valid && tokenLive.Int64 != 0 && tokenEnc.Valid && h.State != nil {
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
	res, err := db.ExecContext(ctx,
		`UPDATE caddy_nodes SET wg_psk_pending_enc = ?, wg_psk_token_hash = ?, wg_psk_token_enc = ?,
		   wg_psk_token_expires = `+store.DateAddMinutes(pskTokenTTLMinutes)+`
		 WHERE id = ?`,
		pskEnc, hex.EncodeToString(sum[:]), tokenEnc, id)
	if err != nil {
		h.Logger.Error("node psk stage", "node_id", id, "err", err)
		redirectWithFlash(w, r, dest, "", "db update failed")
		return
	}
	// A stale node id stages nothing; without this the page still flashes a
	// rekey command that can never work and writes a success audit row.
	if n, _ := res.RowsAffected(); n == 0 {
		redirectWithFlash(w, r, dest, "", "node not found")
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
	// Keep the current state: if the render fails we put it back, so the
	// database never claims the key is gone while our wg0.conf still carries
	// it. Recovery advice is only safe once our own side really changed.
	var prevActive, prevPending, prevTokenHash, prevTokenEnc sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT wg_psk_enc, wg_psk_pending_enc, wg_psk_token_hash, wg_psk_token_enc
		 FROM caddy_nodes WHERE id = ?`, id,
	).Scan(&prevActive, &prevPending, &prevTokenHash, &prevTokenEnc); err != nil {
		redirectWithFlash(w, r, dest, "", "node not found")
		return
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE caddy_nodes SET wg_psk_enc = NULL, wg_psk_pending_enc = NULL, wg_psk_token_hash = NULL,
		   wg_psk_token_enc = NULL, wg_psk_token_expires = NULL WHERE id = ?`, id); err != nil {
		redirectWithFlash(w, r, dest, "", "db update failed")
		return
	}
	if h.WriteWGConfig != nil {
		if werr := h.WriteWGConfig(ctx); werr != nil {
			h.Logger.Error("node psk clear: wg render failed, restoring previous state", "node_id", id, "err", werr)
			cctx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer ccancel()
			if _, cerr := db.ExecContext(cctx,
				`UPDATE caddy_nodes SET wg_psk_enc = ?, wg_psk_pending_enc = ?, wg_psk_token_hash = ?,
				   wg_psk_token_enc = ? WHERE id = ?`,
				prevActive, prevPending, prevTokenHash, prevTokenEnc, id); cerr != nil {
				h.Logger.Error("node psk clear: RESTORE FAILED - panel config and database disagree on this node's PSK",
					"node_id", id, "err", cerr)
				audit.Write(cctx, db, h.Logger, r, audit.Entry{
					UserID: actorUserID(middleware.SessionFromContext(r.Context())),
					Action: "node.psk.clear.failed", Entity: "node", EntityID: strconv.FormatInt(id, 10),
					Meta: map[string]any{"render_err": werr.Error(), "restore_err": cerr.Error()},
				})
			}
			// No node-side command here on purpose: stripping the key on the
			// node while our config still has it is what takes the mesh down.
			redirectWithFlash(w, r, dest, "",
				"PSK not cleared: the panel WireGuard config could not be written, so nothing changed. Do not remove the key on the node yet - retry, and check the panel logs if it keeps failing.")
			return
		}
	}
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(middleware.SessionFromContext(r.Context())),
		Action: "node.psk.clear", Entity: "node", EntityID: strconv.FormatInt(id, 10),
	})
	// `wg syncconf` can set or change a PresharedKey but never removes one
	// (an absent line means "keep the current key"), so the node needs both
	// the file edit - for the next `wg-quick up` - and an explicit
	// `wg set ... preshared-key /dev/null` against the live interface.
	peer := "<the panel's WireGuard public key, from Settings -> WireGuard>"
	if h.WG != nil {
		if cp, cerr := h.WG.Get(ctx); cerr == nil && cp.PublicKey != "" {
			peer = cp.PublicKey
		}
	}
	redirectWithFlash(w, r, dest,
		fmt.Sprintf("Mesh PSK cleared on the panel. The node still has it - run: sed -i '/^PresharedKey/d' /etc/wireguard/wg0.conf && wg set wg0 peer %s preshared-key /dev/null", peer),
		"")
}
