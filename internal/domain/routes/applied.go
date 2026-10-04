package routes

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// Per-node apply state, as opposed to the compile outcome: what each node
// actually accepted on its last /load.
const (
	ApplyApplied = "applied"
	ApplyPending = "pending"
	ApplyFailed  = "failed"
	ApplyUnknown = "unknown"
)

// NodeApply is one node's view of a route: did that node's last /load land.
type NodeApply struct {
	NodeID   int64
	NodeName string
	State    string
	Hash     string
	At       time.Time
	Error    string
	// Attempts is the failed drain count of a durable push marker; -1 = none.
	Attempts int
}

// maxApplyErrLen bounds the stored push error; Caddy can echo large bodies.
const maxApplyErrLen = 1000

// recordNodeApply persists the outcome of a /load on nodeID. Best-effort: the
// push result itself is already decided, bookkeeping must not change it.
func (s *Service) recordNodeApply(ctx context.Context, nodeID int64, hash string, loadErr error) {
	if s.DB == nil {
		return
	}
	now := time.Now().UTC()
	var err error
	if loadErr == nil {
		_, err = s.DB.ExecContext(ctx,
			`UPDATE caddy_nodes SET config_applied_hash=?, config_applied_at=?,
			        config_apply_error=NULL, config_apply_error_at=NULL WHERE id=?`,
			hash, now, nodeID)
	} else {
		msg := loadErr.Error()
		if len(msg) > maxApplyErrLen {
			msg = strings.ToValidUTF8(msg[:maxApplyErrLen], "")
		}
		_, err = s.DB.ExecContext(ctx,
			`UPDATE caddy_nodes SET config_apply_error=?, config_apply_error_at=? WHERE id=?`,
			msg, now, nodeID)
	}
	if err != nil && s.Logger != nil {
		s.Logger.Warn("node apply state not recorded", "node_id", nodeID, "err", err)
	}
}

// NodeApplyStates returns, per route, the apply state of every enabled node
// that should serve it (anchor node plus fan-out assignments).
func (s *Service) NodeApplyStates(ctx context.Context, ids []int64) (map[int64][]NodeApply, error) {
	out := map[int64][]NodeApply{}
	if s.DB == nil || len(ids) == 0 {
		return out, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, 0, 2*len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	args = append(args, args...)
	cols := `n.id, n.name, COALESCE(n.config_applied_hash,''), n.config_applied_at, COALESCE(n.config_apply_error,''), COALESCE(p.attempts,-1)`
	pj := ` LEFT JOIN node_push_pending p ON p.node_id = n.id`
	rows, err := s.DB.QueryContext(ctx,
		`SELECT r.id, `+cols+` FROM routes r JOIN caddy_nodes n ON n.id = r.caddy_node_id`+pj+`
		  WHERE r.id IN (`+ph+`) AND n.is_enabled = 1
		 UNION
		 SELECT a.route_id, `+cols+` FROM route_node_assignments a JOIN caddy_nodes n ON n.id = a.node_id`+pj+`
		  WHERE a.route_id IN (`+ph+`) AND n.is_enabled = 1`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var rid int64
		var na NodeApply
		var at sql.NullTime
		if err := rows.Scan(&rid, &na.NodeID, &na.NodeName, &na.Hash, &at, &na.Error, &na.Attempts); err != nil {
			return nil, err
		}
		na.At = at.Time
		switch {
		case na.Error != "":
			na.State = ApplyFailed
		case na.Attempts >= 0 || s.currentGen(na.NodeID) > s.AppliedGeneration(na.NodeID):
			na.State = ApplyPending
		case !at.Valid:
			na.State = ApplyUnknown
		default:
			na.State = ApplyApplied
		}
		out[rid] = append(out[rid], na)
	}
	return out, rows.Err()
}
