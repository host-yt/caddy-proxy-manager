package handlers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AuditExport streams audit_log rows as CSV or JSON.
// GET /admin/audit/export — same filter params as AuditList plus format and limit.
func (h *AdminHandlers) AuditExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	entity := strings.TrimSpace(q.Get("entity"))
	actionLike := strings.TrimSpace(q.Get("action"))
	actorLike := strings.TrimSpace(q.Get("actor"))
	sinceRaw := strings.TrimSpace(q.Get("since"))
	untilRaw := strings.TrimSpace(q.Get("until"))
	// Parse since/until before use: MySQL coerces invalid strings to 0000-00-00,
	// which would match all rows. Accept YYYY-MM-DD or RFC3339.
	parseDateParam := func(s string) (string, bool) {
		if s == "" {
			return "", true
		}
		for _, layout := range []string{"2006-01-02", time.RFC3339} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC().Format(time.RFC3339), true
			}
		}
		return "", false
	}
	since, sinceOK := parseDateParam(sinceRaw)
	until, untilOK := parseDateParam(untilRaw)
	if !sinceOK || !untilOK {
		http.Error(w, "since/until must be YYYY-MM-DD or RFC3339", http.StatusBadRequest)
		return
	}
	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if format != "json" {
		format = "csv"
	}
	limit := 10_000
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 50_000 {
			limit = n
		}
	}

	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}

	where := []string{"1=1"}
	args := []any{}
	if entity != "" {
		where = append(where, "a.entity = ?")
		args = append(args, entity)
	}
	if actionLike != "" {
		where = append(where, "a.action LIKE ?")
		args = append(args, "%"+actionLike+"%")
	}
	if actorLike != "" {
		where = append(where, "(u.email LIKE ? OR a.actor_type = ?)")
		args = append(args, "%"+actorLike+"%", actorLike)
	}
	if since != "" {
		where = append(where, "a.created_at >= ?")
		args = append(args, since)
	}
	if until != "" {
		where = append(where, "a.created_at < ?")
		args = append(args, until)
	}

	sqlStr := `SELECT DATE_FORMAT(a.created_at,'%Y-%m-%dT%H:%i:%sZ'),
	                  COALESCE(u.email, a.actor_type),
	                  a.actor_type,
	                  a.action, a.entity,
	                  COALESCE(a.entity_id,''),
	                  COALESCE(a.ip,''),
	                  COALESCE(a.user_agent,''),
	                  COALESCE(a.meta,'')
	           FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
	           WHERE ` + strings.Join(where, " AND ") + `
	           ORDER BY a.id ASC LIMIT ?`
	args = append(args, limit)

	// 60 s budget: large exports on slow DB should still drain before timeout.
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		h.Logger.Error("audit export query", "err", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	filename := "audit_" + time.Now().UTC().Format("20060102_150405")

	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`.json"`)
		enc := json.NewEncoder(w)
		_, _ = w.Write([]byte("[\n"))
		first := true
		for rows.Next() {
			var ts, actor, actorType, action, entity, entityID, ip, ua, meta string
			if err := rows.Scan(&ts, &actor, &actorType, &action, &entity, &entityID, &ip, &ua, &meta); err != nil {
				continue
			}
			if !first {
				_, _ = w.Write([]byte(",\n"))
			}
			first = false
			_ = enc.Encode(map[string]string{
				"timestamp":  ts,
				"actor":      actor,
				"actor_type": actorType,
				"action":     action,
				"entity":     entity,
				"entity_id":  entityID,
				"ip":         ip,
				"user_agent": ua,
				"meta":       meta,
			})
		}
		_, _ = w.Write([]byte("]\n"))
		return
	}

	// Default: CSV
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"timestamp", "actor", "actor_type", "action", "entity", "entity_id", "ip", "user_agent", "meta"})
	for rows.Next() {
		var ts, actor, actorType, action, entity, entityID, ip, ua, meta string
		if err := rows.Scan(&ts, &actor, &actorType, &action, &entity, &entityID, &ip, &ua, &meta); err != nil {
			continue
		}
		_ = cw.Write([]string{ts, actor, actorType, action, entity, entityID, ip, ua, meta})
	}
	cw.Flush()
}
