package store

import (
	"regexp"
	"strings"
)

// The MySQL migrations wrap conditional DDL in procedural guards
// ("IF NOT EXISTS (information_schema...) THEN ALTER TABLE ... ADD COLUMN").
// SQLite has no procedural IF and no ADD COLUMN IF NOT EXISTS, so the transform
// drops the guard and keeps the body. That is only sound if the guard would
// actually have passed: plans.wildcard_enabled, for one, is already created by
// migration 1, so migration 41's re-add aborts the install on SQLite.
//
// schemaTracker replays the migrations in version order, keeping the column and
// index sets the guards would have inspected, and resolves the conditions that
// SQLite cannot express itself:
//
//   - ADD COLUMN of a column already present  -> dropped (guard would skip it)
//   - DROP COLUMN of a column already absent  -> dropped (same)
//   - DROP COLUMN still covered by an index   -> preceded by DROP INDEX, which
//     MySQL does implicitly but SQLite refuses to
type schemaTracker struct {
	cols    map[string]map[string]bool // table -> column set
	indexes map[string]sqliteIndex     // index name -> definition
}

type sqliteIndex struct {
	table string
	cols  []string
}

func newSchemaTracker() *schemaTracker {
	return &schemaTracker{
		cols:    map[string]map[string]bool{},
		indexes: map[string]sqliteIndex{},
	}
}

var (
	reStmtCreateTable = regexp.MustCompile("(?is)^\\s*CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?[`\"]?(\\w+)[`\"]?\\s*\\((.*)\\)\\s*$")
	reStmtCreateIndex = regexp.MustCompile("(?is)^\\s*CREATE\\s+(?:UNIQUE\\s+)?INDEX\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?[`\"]?(\\w+)[`\"]?\\s+ON\\s+[`\"]?(\\w+)[`\"]?\\s*\\(([^)]*)\\)\\s*$")
	reStmtDropTable   = regexp.MustCompile("(?is)^\\s*DROP\\s+TABLE\\s+(?:IF\\s+EXISTS\\s+)?[`\"]?(\\w+)[`\"]?\\s*$")
	reStmtDropIndex   = regexp.MustCompile("(?is)^\\s*DROP\\s+INDEX\\s+(?:IF\\s+EXISTS\\s+)?[`\"]?(\\w+)[`\"]?\\s*$")
	reStmtAddColumn   = regexp.MustCompile("(?is)^\\s*ALTER\\s+TABLE\\s+[`\"]?(\\w+)[`\"]?\\s+ADD\\s+(?:COLUMN\\s+)?[`\"]?(\\w+)[`\"]?\\b")
	reStmtDropColumn  = regexp.MustCompile("(?is)^\\s*ALTER\\s+TABLE\\s+[`\"]?(\\w+)[`\"]?\\s+DROP\\s+(?:COLUMN\\s+)?[`\"]?(\\w+)[`\"]?\\s*$")
	reStmtRenameTable = regexp.MustCompile("(?is)^\\s*ALTER\\s+TABLE\\s+[`\"]?(\\w+)[`\"]?\\s+RENAME\\s+TO\\s+[`\"]?(\\w+)[`\"]?\\s*$")
	reFirstWord       = regexp.MustCompile(`^\s*[` + "`" + `"]?(\w+)`)
)

// nonColumnClause reports whether a CREATE TABLE clause is a table constraint
// rather than a column definition.
func nonColumnClause(upper string) bool {
	for _, kw := range []string{"PRIMARY KEY", "UNIQUE", "CONSTRAINT", "FOREIGN KEY", "CHECK", "KEY ", "INDEX "} {
		if strings.HasPrefix(upper, kw) {
			return true
		}
	}
	return false
}

func (s *schemaTracker) addCol(table, col string) {
	if s.cols[table] == nil {
		s.cols[table] = map[string]bool{}
	}
	s.cols[table][strings.ToLower(col)] = true
}

func (s *schemaTracker) hasCol(table, col string) bool {
	return s.cols[table][strings.ToLower(col)]
}

// knownTable reports whether the tracker ever saw the table created. Statements
// on unknown tables are left alone rather than guessed at.
func (s *schemaTracker) knownTable(table string) bool {
	_, ok := s.cols[table]
	return ok
}

// apply walks one migration's Up section, updating the tracked schema and
// rewriting the statements SQLite would otherwise choke on. The Down section is
// returned untouched: it never runs on the fresh installs SQLite is used for,
// and replaying its drops would desync the tracker.
func (s *schemaTracker) apply(sqlText string) string {
	up, down := sqlText, ""
	if i := strings.Index(sqlText, "-- +goose Down"); i >= 0 {
		up, down = sqlText[:i], sqlText[i:]
	}

	parts := strings.Split(up, ";")
	out := make([]string, 0, len(parts))
	for _, stmt := range parts {
		kept, extra := s.visit(stmt)
		out = append(out, extra...)
		if kept != "" {
			out = append(out, kept)
		}
	}
	return strings.Join(out, ";") + down
}

// visit returns the (possibly emptied) statement plus any statements that must
// run before it.
func (s *schemaTracker) visit(stmt string) (kept string, before []string) {
	// Analyse without comments; emit the original so annotations survive.
	bare := strings.TrimSpace(reLineComment.ReplaceAllString(stmt, ""))
	if bare == "" {
		return stmt, nil
	}

	if m := reStmtCreateTable.FindStringSubmatch(bare); m != nil {
		table := m[1]
		if s.cols[table] == nil {
			s.cols[table] = map[string]bool{}
		}
		for _, clause := range splitAlterClauses(m[2]) {
			clause = strings.TrimSpace(clause)
			if clause == "" || nonColumnClause(strings.ToUpper(clause)) {
				continue
			}
			if cm := reFirstWord.FindStringSubmatch(clause); cm != nil {
				s.addCol(table, cm[1])
			}
		}
		return stmt, nil
	}

	if m := reStmtCreateIndex.FindStringSubmatch(bare); m != nil {
		var cols []string
		for _, c := range strings.Split(m[3], ",") {
			if cm := reFirstWord.FindStringSubmatch(strings.TrimSpace(c)); cm != nil {
				cols = append(cols, strings.ToLower(cm[1]))
			}
		}
		s.indexes[m[1]] = sqliteIndex{table: m[2], cols: cols}
		return stmt, nil
	}

	if m := reStmtDropIndex.FindStringSubmatch(bare); m != nil {
		delete(s.indexes, m[1])
		return stmt, nil
	}

	if m := reStmtDropTable.FindStringSubmatch(bare); m != nil {
		delete(s.cols, m[1])
		for name, idx := range s.indexes {
			if idx.table == m[1] {
				delete(s.indexes, name)
			}
		}
		return stmt, nil
	}

	if m := reStmtRenameTable.FindStringSubmatch(bare); m != nil {
		if cols, ok := s.cols[m[1]]; ok {
			s.cols[m[2]] = cols
			delete(s.cols, m[1])
		}
		return stmt, nil
	}

	if m := reStmtDropColumn.FindStringSubmatch(bare); m != nil {
		table, col := m[1], m[2]
		if s.knownTable(table) && !s.hasCol(table, col) {
			return "", nil // guard would have skipped it
		}
		// SQLite refuses to drop a column an index still covers.
		for name, idx := range s.indexes {
			if idx.table != table {
				continue
			}
			for _, c := range idx.cols {
				if c == strings.ToLower(col) {
					before = append(before, "\nDROP INDEX IF EXISTS "+name)
					delete(s.indexes, name)
					break
				}
			}
		}
		delete(s.cols[table], strings.ToLower(col))
		return stmt, before
	}

	if m := reStmtAddColumn.FindStringSubmatch(bare); m != nil {
		table, col := m[1], m[2]
		if s.hasCol(table, col) {
			return "", nil // guard would have skipped it
		}
		s.addCol(table, col)
		return stmt, nil
	}

	return stmt, nil
}
