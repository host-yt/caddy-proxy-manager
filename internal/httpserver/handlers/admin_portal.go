package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/portal"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// accessGroupsData is the /admin/access-groups page payload.
type accessGroupsData struct {
	baseAdminData
	Groups       []accessGroupRow
	Clients      []clientOption // for the owning-client picker (super_admin)
	IsSuperAdmin bool
}

type accessGroupRow struct {
	portal.Group
	ClientName string
	Members    []portal.Member
}

// canManageGroup returns true when the caller may manage a group: super_admin
// always; scoped admins only when the group's owning client is in their scope.
// Global groups (client_id NULL) are super_admin-only. Fail closed on errors.
func (h *AdminHandlers) canManageGroup(ctx context.Context, sess *auth.Session, groupID int64) bool {
	if h.Portal == nil {
		return false
	}
	if sess != nil && sess.Role == "super_admin" {
		return true
	}
	cid, ok, err := h.Portal.GroupClientID(ctx, groupID)
	if err != nil || !ok {
		return false // missing/global group or error => only super_admin (handled above)
	}
	allowed, all, okScope := h.adminClientScope(ctx, sess)
	if !okScope {
		return false
	}
	return all || allowed[cid]
}

// AccessGroupsList renders /admin/access-groups.
func (h *AdminHandlers) AccessGroupsList(w http.ResponseWriter, r *http.Request) {
	d := accessGroupsData{baseAdminData: h.base(r, "Access groups")}
	if h.Portal == nil {
		h.render(w, "access_groups", d)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	allowed, all, ok := h.adminClientScope(ctx, sess)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	d.IsSuperAdmin = sess != nil && sess.Role == "super_admin"
	var clientIDs []int64
	if !all {
		for id := range allowed {
			clientIDs = append(clientIDs, id)
		}
	}
	groups, err := h.Portal.ListGroups(ctx, clientIDs, all)
	if err != nil {
		h.Logger.Warn("access groups list", "err", err)
	}
	names := h.clientNames(ctx)
	for _, g := range groups {
		row := accessGroupRow{Group: g}
		if g.ClientID.Valid {
			row.ClientName = names[g.ClientID.Int64]
		}
		row.Members, _ = h.Portal.Members(ctx, g.ID)
		d.Groups = append(d.Groups, row)
	}
	if d.IsSuperAdmin {
		d.Clients = loadClientOptions(ctx, h.DB())
	}
	h.render(w, "access_groups", d)
}

// AccessGroupsCreate handles POST /admin/access-groups.
func (h *AdminHandlers) AccessGroupsCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	clientID, _ := strconv.ParseInt(r.FormValue("client_id"), 10, 64)
	if name == "" || len(name) > 128 {
		redirectWithFlash(w, r, "/admin/access-groups", "", "group name required (<=128 chars)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	// Scope: a non-super_admin must own the target client; they cannot create
	// a global (client_id=0) group.
	if sess == nil || sess.Role != "super_admin" {
		allowed, all, ok := h.adminClientScope(ctx, sess)
		if !ok || all == false && (clientID <= 0 || !allowed[clientID]) {
			redirectWithFlash(w, r, "/admin/access-groups", "", "you can only create groups for your own clients")
			return
		}
	}
	id, err := h.Portal.CreateGroup(ctx, name, desc, clientID)
	if err != nil {
		redirectWithFlash(w, r, "/admin/access-groups", "", "create failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "portal.group.create", Entity: "access_group",
		EntityID: itoa64(id), Meta: map[string]any{"name": name, "client_id": clientID},
	})
	redirectWithFlash(w, r, "/admin/access-groups", "group created", "")
}

// AccessGroupsDelete handles POST /admin/access-groups/{id}/delete.
func (h *AdminHandlers) AccessGroupsDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.canManageGroup(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := h.Portal.DeleteGroup(ctx, id); err != nil {
		redirectWithFlash(w, r, "/admin/access-groups", "", "delete failed")
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "portal.group.delete", Entity: "access_group", EntityID: itoa64(id),
	})
	redirectWithFlash(w, r, "/admin/access-groups", "group deleted", "")
}

// AccessGroupMemberAdd handles POST /admin/access-groups/{id}/members.
func (h *AdminHandlers) AccessGroupMemberAdd(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.canManageGroup(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if email == "" {
		redirectWithFlash(w, r, "/admin/access-groups", "", "email required")
		return
	}
	added, err := h.Portal.AddMemberByEmail(ctx, id, email)
	if err != nil {
		redirectWithFlash(w, r, "/admin/access-groups", "", "add failed")
		return
	}
	if !added {
		redirectWithFlash(w, r, "/admin/access-groups", "", "no active user with that email")
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "portal.group.member.add", Entity: "access_group",
		EntityID: itoa64(id), Meta: map[string]any{"email": maskEmail(email)},
	})
	redirectWithFlash(w, r, "/admin/access-groups", "member added", "")
}

// AccessGroupMemberRemove handles POST /admin/access-groups/{id}/members/{uid}/delete.
func (h *AdminHandlers) AccessGroupMemberRemove(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	uid, _ := strconv.ParseInt(chi.URLParam(r, "uid"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	sess := middleware.SessionFromContext(r.Context())
	if !h.canManageGroup(ctx, sess, id) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := h.Portal.RemoveMember(ctx, id, uid); err != nil {
		redirectWithFlash(w, r, "/admin/access-groups", "", "remove failed")
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "portal.group.member.remove", Entity: "access_group",
		EntityID: itoa64(id), Meta: map[string]any{"user_id": uid},
	})
	redirectWithFlash(w, r, "/admin/access-groups", "member removed", "")
}

// portalGroupOption is one selectable group on the host-editor Portal tab.
type portalGroupOption struct {
	ID          int64
	Name        string
	MemberCount int
	Granted     bool
}

// portalGroupsForRoute returns the groups the host editor may grant to a route
// (the route's owning-client groups + global groups) with their current grant
// state. Used to render the per-host Portal tab.
func (h *AdminHandlers) portalGroupsForRoute(ctx context.Context, sess *auth.Session, routeID, clientID int64) []portalGroupOption {
	if h.Portal == nil {
		return nil
	}
	// Visible groups: owned by the route's client; super_admin also sees globals.
	includeGlobal := sess != nil && sess.Role == "super_admin"
	all, _ := h.Portal.GroupsForGrant(ctx, clientID, includeGlobal)
	granted, _ := h.Portal.RouteGrants(ctx, routeID)
	grantedSet := make(map[int64]bool, len(granted))
	for _, g := range granted {
		grantedSet[g] = true
	}
	out := make([]portalGroupOption, 0, len(all))
	for _, g := range all {
		out = append(out, portalGroupOption{ID: g.ID, Name: g.Name, MemberCount: g.MemberCount, Granted: grantedSet[g.ID]})
	}
	return out
}

// ---- helpers ------------------------------------------------------------

// clientNames returns id->display_name for all clients (small table).
func (h *AdminHandlers) clientNames(ctx context.Context) map[int64]string {
	out := map[int64]string{}
	db := h.DB()
	if db == nil {
		return out
	}
	rows, err := db.QueryContext(ctx, `SELECT id, COALESCE(display_name,'') FROM clients`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name string
		if rows.Scan(&id, &name) == nil {
			out[id] = name
		}
	}
	return out
}
