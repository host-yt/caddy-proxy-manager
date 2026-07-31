package handlers

import (
	"context"
	"database/sql"
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
)

// legacyAliasRow is one route whose aliases lost their backfilled proof in
// migration 00138. Pending = still not serving those aliases.
type legacyAliasRow struct {
	RouteID  int64
	Domain   string
	Client   string
	NodeName string
	Status   string
	// Claimed is the alias set 00136 marked proven without any TXT check;
	// Unproven is the subset that is still not serving today.
	Claimed  []string
	Unproven []string
	Created  string
}

type legacyAliasData struct {
	baseAdminData
	Rows        []legacyAliasRow
	PendingCnt  int
	ResolvedCnt int
}

// legacyAliasesQuery lists parked claims joined with the route's current state.
const legacyAliasesQuery = `
	SELECT c.route_id, c.aliases, c.status, DATE_FORMAT(c.created_at,'%Y-%m-%d %H:%i'),
	       COALESCE(r.domain,''), COALESCE(r.aliases,''), COALESCE(r.aliases_verified,''),
	       COALESCE(NULLIF(cl.display_name,''), COALESCE(u.email,'')), COALESCE(n.name,'')
	  FROM route_alias_legacy_claims c
	  LEFT JOIN routes r      ON r.id = c.route_id
	  LEFT JOIN services s    ON s.id = r.service_id
	  LEFT JOIN clients cl    ON cl.id = s.client_id
	  LEFT JOIN users u       ON u.id = cl.user_id
	  LEFT JOIN caddy_nodes n ON n.id = r.caddy_node_id
	 ORDER BY c.status ASC, c.route_id ASC LIMIT 5000`

// loadLegacyAliasRows runs legacyAliasesQuery and shapes it for the page/CSV.
func loadLegacyAliasRows(ctx context.Context, db *sql.DB) []legacyAliasRow {
	rows, err := db.QueryContext(ctx, legacyAliasesQuery)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []legacyAliasRow
	for rows.Next() {
		var (
			e                 legacyAliasRow
			claimed           string
			current, verified string
		)
		if rows.Scan(&e.RouteID, &claimed, &e.Status, &e.Created,
			&e.Domain, &current, &verified, &e.Client, &e.NodeName) != nil {
			continue
		}
		e.Claimed = splitHostCSV(claimed)
		// Only aliases the route still carries can be "not serving"; a removed
		// one is not an outage.
		for _, a := range splitHostCSV(current) {
			if !contains(splitHostCSV(verified), a) && contains(e.Claimed, a) {
				e.Unproven = append(e.Unproven, a)
			}
		}
		out = append(out, e)
	}
	return out
}

// contains reports whether list holds v.
func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// LegacyAliasesPage GET /admin/legacy-aliases (super_admin only). The recovery
// report for migration 00138: which aliases stopped serving and why.
func (h *AdminHandlers) LegacyAliasesPage(w http.ResponseWriter, r *http.Request) {
	if h.guardSuperAdmin(w, r) == nil {
		return
	}
	d := legacyAliasData{baseAdminData: h.base(r, "Legacy alias review")}
	d.PageDesc = "Aliases that were trusted before per-alias ownership proof existed"
	db := h.DB()
	if db == nil {
		h.render(w, "legacy_aliases", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	d.Rows = loadLegacyAliasRows(ctx, db)
	for _, row := range d.Rows {
		if row.Status == "pending" {
			d.PendingCnt++
		} else {
			d.ResolvedCnt++
		}
	}
	h.render(w, "legacy_aliases", d)
}

// LegacyAliasesExport GET /admin/legacy-aliases/export.csv (super_admin only).
func (h *AdminHandlers) LegacyAliasesExport(w http.ResponseWriter, r *http.Request) {
	if h.guardSuperAdmin(w, r) == nil {
		return
	}
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="hpg-legacy-aliases.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"route_id", "domain", "client", "node", "status", "claimed_aliases", "not_serving", "recorded_at"})
	for _, row := range loadLegacyAliasRows(ctx, db) {
		_ = cw.Write(csvSafeRow([]string{
			strconv.FormatInt(row.RouteID, 10), row.Domain, row.Client, row.NodeName, row.Status,
			strings.Join(row.Claimed, " "), strings.Join(row.Unproven, " "), row.Created,
		}))
	}
	cw.Flush()
}

// LegacyAliasApprove POST /admin/legacy-aliases/{id}/approve (super_admin only).
// The operator vouches for the claim: the still-present aliases become proven
// again and the route serves them on the next push.
func (h *AdminHandlers) LegacyAliasApprove(w http.ResponseWriter, r *http.Request) {
	sess := h.guardSuperAdmin(w, r)
	if sess == nil {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	n, err := h.approveLegacyAliases(ctx, actorUserID(sess), id)
	if err != nil {
		redirectWithFlash(w, r, "/admin/legacy-aliases", "", "approve failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "legacy_alias.approve", Entity: "route",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, "/admin/legacy-aliases", strconv.Itoa(n)+" route(s) approved.", "")
}

// LegacyAliasApproveAll POST /admin/legacy-aliases/approve-all (super_admin only).
func (h *AdminHandlers) LegacyAliasApproveAll(w http.ResponseWriter, r *http.Request) {
	sess := h.guardSuperAdmin(w, r)
	if sess == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	n, err := h.approveLegacyAliases(ctx, actorUserID(sess), 0)
	if err != nil {
		redirectWithFlash(w, r, "/admin/legacy-aliases", "", "approve failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "legacy_alias.approve_all", Entity: "route",
		Meta: map[string]any{"routes": n},
	})
	redirectWithFlash(w, r, "/admin/legacy-aliases", strconv.Itoa(n)+" route(s) approved.", "")
}

// LegacyAliasDismiss POST /admin/legacy-aliases/{id}/dismiss (super_admin only).
// Closes the claim without restoring proof; the owner must publish the TXT.
func (h *AdminHandlers) LegacyAliasDismiss(w http.ResponseWriter, r *http.Request) {
	sess := h.guardSuperAdmin(w, r)
	if sess == nil {
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := h.DB().ExecContext(ctx,
		`UPDATE route_alias_legacy_claims SET status='dismissed', resolved_at=NOW(), resolved_by=?
		  WHERE route_id=? AND status='pending'`, actorUserID(sess), id); err != nil {
		redirectWithFlash(w, r, "/admin/legacy-aliases", "", "dismiss failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "legacy_alias.dismiss", Entity: "route",
		EntityID: strconv.FormatInt(id, 10),
	})
	redirectWithFlash(w, r, "/admin/legacy-aliases", "Claim dismissed.", "")
}

// approveLegacyAliases restores proof for one pending claim, or all of them
// when routeID is 0. Returns how many routes were touched.
func (h *AdminHandlers) approveLegacyAliases(ctx context.Context, actor *int64, routeID int64) (int, error) {
	db := h.DB()
	if db == nil {
		return 0, sql.ErrConnDone
	}
	q := `SELECT c.route_id, c.aliases, COALESCE(r.aliases,''), COALESCE(r.aliases_verified,''),
	             COALESCE(r.caddy_node_id,0)
	        FROM route_alias_legacy_claims c
	        LEFT JOIN routes r ON r.id = c.route_id
	       WHERE c.status='pending'`
	args := []any{}
	if routeID > 0 {
		q += " AND c.route_id = ?"
		args = append(args, routeID)
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	type job struct {
		id, node int64
		merged   string
	}
	var jobs []job
	for rows.Next() {
		var (
			j                          job
			claimed, current, verified string
		)
		if rows.Scan(&j.id, &claimed, &current, &verified, &j.node) != nil {
			continue
		}
		// Approve only what the route still lists: an alias added after the
		// migration never carried a legacy claim and must prove itself.
		keep := splitHostCSV(verified)
		for _, a := range splitHostCSV(current) {
			if contains(splitHostCSV(claimed), a) && !contains(keep, a) {
				keep = append(keep, a)
			}
		}
		j.merged = strings.Join(keep, ",")
		jobs = append(jobs, j)
	}
	rows.Close()
	touched := map[int64]struct{}{}
	for _, j := range jobs {
		if _, err := db.ExecContext(ctx,
			"UPDATE routes SET aliases_verified=? WHERE id=?", j.merged, j.id); err != nil {
			return 0, err
		}
		if _, err := db.ExecContext(ctx,
			`UPDATE route_alias_legacy_claims SET status='approved', resolved_at=NOW(), resolved_by=?
			  WHERE route_id=?`, actor, j.id); err != nil {
			return 0, err
		}
		if j.node > 0 {
			touched[j.node] = struct{}{}
		}
	}
	if h.Routes != nil {
		for n := range touched {
			h.Routes.SchedulePush(n)
		}
	}
	return len(jobs), nil
}
