package store

import (
	"regexp"
	"strings"
)

// TransformForSQLite converts MySQL-dialect SQL to SQLite-compatible SQL.
// Used at migration time when the active driver is "sqlite3".
func TransformForSQLite(input string) string {
	// Comments go first, so no later pattern can trip over their content: a
	// comment carrying a ";" truncated the ALTER that followed it, one carrying
	// a "," split a clause, and DDL-looking prose parsed as DDL.
	input = stripSQLComments(input)
	// Handle stored procedures first (they wrap everything).
	if containsProcedure(input) {
		input = unwrapProcedures(input)
	}
	// Strip precision args: DATETIME(3) → DATETIME, CURRENT_TIMESTAMP(3) → CURRENT_TIMESTAMP.
	input = reDatetimePrecision.ReplaceAllString(input, "$1")
	input = reCurrentTimestampPrec.ReplaceAllString(input, "CURRENT_TIMESTAMP")
	// Convert inline CREATE TABLE indexes.
	input = convertCreateTableIndexes(input)
	// Strip MySQL table options from CREATE TABLE endings.
	input = stripMySQLTableOptions(input)
	// Convert AUTO_INCREMENT PKs and strip UNSIGNED.
	input = fixAutoIncrementPK(input)
	// Rewrite ALTER TABLE (split multi-clause, strip AFTER, convert ADD KEY).
	input = fixAlterTable(input)
	// INSERT IGNORE -> INSERT OR IGNORE.
	input = strings.ReplaceAll(input, "INSERT IGNORE INTO", "INSERT OR IGNORE INTO")
	input = strings.ReplaceAll(input, "insert ignore into", "INSERT OR IGNORE INTO")
	// ON DUPLICATE KEY UPDATE.
	input = fixOnDuplicateKey(input)
	// Remove ON UPDATE CURRENT_TIMESTAMP (no DDL triggers in SQLite).
	input = reOnUpdate.ReplaceAllString(input, "")
	// NOW()/UTC_TIMESTAMP() -> CURRENT_TIMESTAMP (SQLite has neither).
	input = reMySQLNow.ReplaceAllString(input, "${1}CURRENT_TIMESTAMP")
	// ENUM(...) -> TEXT.
	input = reEnum.ReplaceAllString(input, "TEXT")
	// Remove any remaining information_schema references that slipped through.
	input = removeInfoSchemaBlocks(input)
	return input
}

var (
	reOnUpdate              = regexp.MustCompile(`(?i)\s+ON\s+UPDATE\s+CURRENT_TIMESTAMP`)
	reEnum                  = regexp.MustCompile(`(?i)ENUM\s*\([^)]+\)`)
	// Leading group keeps a qualified call like Go's time.Now() in a comment intact.
	reMySQLNow              = regexp.MustCompile(`(?i)(^|[^.\w])(?:NOW|UTC_TIMESTAMP)\s*\(\s*\)`)
	reInsertInto            = regexp.MustCompile(`(?i)^(\s*)INSERT\s+INTO\s+`)
	// SQLite doesn't support precision args: DATETIME(3) → DATETIME, CURRENT_TIMESTAMP(3) → CURRENT_TIMESTAMP.
	reDatetimePrecision     = regexp.MustCompile(`(?i)\b(DATETIME|TIMESTAMP|TIME|DATE)\s*\(\d+\)`)
	reCurrentTimestampPrec  = regexp.MustCompile(`(?i)\bCURRENT_TIMESTAMP\s*\(\d+\)`)
)

// stripSQLComments removes `--` comments, keeping the "-- +goose" annotations
// that delimit the Up/Down sections. No migration puts "--" inside a string
// literal, so cutting at the first occurrence is safe.
func stripSQLComments(input string) string {
	lines := strings.Split(input, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "-- +goose") {
			continue
		}
		if idx := strings.Index(line, "--"); idx >= 0 {
			lines[i] = strings.TrimRight(line[:idx], " \t")
		}
	}
	return strings.Join(lines, "\n")
}

// containsProcedure returns true if the SQL contains a stored procedure.
func containsProcedure(sql string) bool {
	return strings.Contains(strings.ToUpper(sql), "CREATE PROCEDURE")
}

// unwrapProcedures extracts SQL statements from stored procedure bodies,
// discarding procedure boilerplate (DROP PROCEDURE, CREATE PROCEDURE, CALL).
// For information_schema IF guards: the condition and END IF are skipped;
// the body DDL (ALTER TABLE etc.) is kept - safe for fresh installs.
func unwrapProcedures(input string) string {
	var result []string
	lines := strings.Split(input, "\n")
	inProcHeader := false
	inProcBody := false
	beginDepth := 0
	// inInfoGuard tracks whether we're inside an IF EXISTS/IF NOT EXISTS block.
	inInfoGuard := false
	// guardPastThen tracks whether we've seen THEN (and are now in the body).
	guardPastThen := false
	// guardNotExists records the guard's polarity, so a NOT EXISTS body can keep
	// its "only if absent" intent via INSERT OR IGNORE once the guard is dropped.
	guardNotExists := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)

		// Skip procedure boilerplate lines.
		if isProceduralBoilerplate(upper) {
			inProcHeader = true
			continue
		}
		if inProcHeader && upper == "BEGIN" {
			inProcHeader = false
			inProcBody = true
			beginDepth = 1
			continue
		}
		if inProcBody {
			// Track nested BEGIN/END.
			if upper == "BEGIN" {
				beginDepth++
				result = append(result, line)
				continue
			}
			if upper == "END;" || upper == "END" {
				beginDepth--
				if beginDepth == 0 {
					inProcBody = false
					inInfoGuard = false
					guardPastThen = false
					guardNotExists = false
				} else {
					result = append(result, line)
				}
				continue
			}
			// Multi-line IF EXISTS/IF NOT EXISTS guard handling.
			if inInfoGuard {
				if !guardPastThen {
					// Still in the SELECT condition; wait for THEN.
					if strings.HasSuffix(upper, "THEN") || upper == "THEN" {
						guardPastThen = true
					}
					continue
				}
				// Past THEN - we're in the body.
				if upper == "END IF;" || upper == "END IF" {
					inInfoGuard = false
					guardPastThen = false
					guardNotExists = false
					continue
				}
				// Keep the inner DDL (ALTER TABLE, etc.).
				if trimmed != "" {
					if guardNotExists {
						line = reInsertInto.ReplaceAllString(line, "${1}INSERT OR IGNORE INTO ")
					}
					result = append(result, line)
				}
				continue
			}
			if isGuardIf(upper) {
				inInfoGuard = true
				guardPastThen = strings.HasSuffix(upper, "THEN")
				guardNotExists = strings.HasPrefix(upper, "IF NOT EXISTS")
				continue
			}
			result = append(result, line)
			continue
		}
		// Outside procedure: keep goose annotations, skip CALL/DROP PROCEDURE lines.
		if strings.HasPrefix(upper, "CALL HPG_") || strings.HasPrefix(upper, "DROP PROCEDURE") {
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

// isProceduralBoilerplate returns true for lines that are procedure shell code.
func isProceduralBoilerplate(upper string) bool {
	return strings.HasPrefix(upper, "DROP PROCEDURE IF EXISTS") ||
		strings.HasPrefix(upper, "DROP PROCEDURE HPG_") ||
		strings.HasPrefix(upper, "CREATE PROCEDURE HPG_") ||
		strings.HasPrefix(upper, "CALL HPG_")
}

// isGuardIf returns true if the line starts an IF (NOT) EXISTS guard. Both the
// information_schema kind ("add the column unless present") and the plain-table
// kind ("seed the row unless present") are dropped: goose applies a migration
// once per DB, so on the fresh install SQLite always gets, the guard condition
// holds by construction.
func isGuardIf(upper string) bool {
	return strings.HasPrefix(upper, "IF NOT EXISTS") || strings.HasPrefix(upper, "IF EXISTS")
}

var reInfoSchemaBlock = regexp.MustCompile(`(?is)IF\s+(NOT\s+)?EXISTS\s*\(\s*SELECT\s+1\s+FROM\s+information_schema[^;]*?\)\s*THEN([^;]*?;)\s*END\s+IF\s*;`)

// removeInfoSchemaBlocks removes IF (NOT) EXISTS (information_schema ...) THEN ... END IF; blocks,
// extracting the body SQL.
func removeInfoSchemaBlocks(input string) string {
	return reInfoSchemaBlock.ReplaceAllStringFunc(input, func(m string) string {
		// Extract the THEN body - everything between THEN and END IF.
		thenIdx := strings.Index(strings.ToUpper(m), "THEN")
		endIdx := strings.LastIndex(strings.ToUpper(m), "END IF")
		if thenIdx < 0 || endIdx < 0 || thenIdx >= endIdx {
			return m
		}
		body := strings.TrimSpace(m[thenIdx+4 : endIdx])
		return body
	})
}

// reCreateTable matches a full CREATE TABLE statement.
var reCreateTable = regexp.MustCompile("(?is)(CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?[^`(]+)\\s*\\((.+?)\\)\\s*(?:ENGINE[^;]*)?;")

// convertCreateTableIndexes transforms inline MySQL index definitions to separate CREATE INDEX statements.
func convertCreateTableIndexes(input string) string {
	return reCreateTable.ReplaceAllStringFunc(input, func(m string) string {
		return transformCreateTable(m)
	})
}

var (
	// Anchored at clause start, so a column named e.g. "pubkey VARCHAR(64)"
	// can never read as a KEY definition.
	reKeyClause = regexp.MustCompile("(?is)^(UNIQUE\\s+)?(?:KEY|INDEX)\\s+([^\\s(]+)\\s*\\((.+)\\)$")
	reLineComment = regexp.MustCompile(`(?m)--[^\n]*`)
	reTableName   = regexp.MustCompile("(?i)CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?[`\"]?(\\w+)[`\"]?\\s*\\(")
)

// transformCreateTable rewrites one CREATE TABLE: inline MySQL KEY/UNIQUE KEY
// definitions become standalone CREATE INDEX statements.
//
// The body is split into top-level clauses and rebuilt rather than regex-erased
// in place: erasing left the surviving clauses' commas dangling (a trailing
// CONSTRAINT then parsed as a syntax error), and was blind to `--` comments,
// which are dropped here since only SQLite reads this output.
func transformCreateTable(stmt string) string {
	nameMatch := reTableName.FindStringSubmatch(stmt)
	sub := reCreateTable.FindStringSubmatch(stmt)
	if nameMatch == nil || sub == nil {
		return stmt
	}
	tableName := nameMatch[1]
	header := strings.TrimRight(sub[1], " \t\n")
	body := reLineComment.ReplaceAllString(sub[2], "")

	var kept, indexes []string
	for _, clause := range splitAlterClauses(body) {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		km := reKeyClause.FindStringSubmatch(clause)
		if km == nil {
			kept = append(kept, clause)
			continue
		}
		unique := ""
		if strings.TrimSpace(km[1]) != "" {
			unique = "UNIQUE "
		}
		idxName := strings.Trim(km[2], "`\"")
		indexes = append(indexes,
			"CREATE "+unique+"INDEX IF NOT EXISTS "+idxName+" ON "+tableName+"("+km[3]+");")
	}
	if len(indexes) == 0 {
		return stmt
	}

	out := header + " (\n    " + strings.Join(kept, ",\n    ") + "\n);"
	return out + "\n" + strings.Join(indexes, "\n")
}

// stripMySQLTableOptions removes ENGINE=..., CHARSET=..., COLLATE=... from CREATE TABLE endings.
func stripMySQLTableOptions(input string) string {
	// Match the end of CREATE TABLE statements: ) <opts>;
	re := regexp.MustCompile(`(?i)(\))\s*(ENGINE\s*=\s*\w+[^;]*)\s*;`)
	return re.ReplaceAllString(input, "$1;")
}

// fixOnDuplicateKey converts ON DUPLICATE KEY UPDATE to ON CONFLICT DO UPDATE.
func fixOnDuplicateKey(input string) string {
	// settings table: simple primary key on "key".
	input = reSettingsDupKey.ReplaceAllStringFunc(input, func(m string) string {
		updateIdx := strings.Index(strings.ToUpper(m), "ON DUPLICATE KEY UPDATE")
		if updateIdx < 0 {
			return m
		}
		insertPart := m[:updateIdx]
		updatePart := m[updateIdx+len("ON DUPLICATE KEY UPDATE"):]
		sqliteCols := convertValuesToExcluded(updatePart)
		return insertPart + `ON CONFLICT("key") DO UPDATE SET` + sqliteCols
	})
	// Generic: any remaining ON DUPLICATE KEY UPDATE - try to convert VALUES() references.
	input = reGenericDupKey.ReplaceAllStringFunc(input, func(m string) string {
		updateIdx := strings.Index(strings.ToUpper(m), "ON DUPLICATE KEY UPDATE")
		if updateIdx < 0 {
			return m
		}
		insertPart := m[:updateIdx]
		updatePart := m[updateIdx+len("ON DUPLICATE KEY UPDATE"):]
		sqliteCols := convertValuesToExcluded(updatePart)
		return insertPart + "ON CONFLICT DO UPDATE SET" + sqliteCols
	})
	return input
}

var (
	reSettingsDupKey = regexp.MustCompile(`(?is)INSERT\s+(?:IGNORE\s+)?INTO\s+settings[^;]+ON\s+DUPLICATE\s+KEY\s+UPDATE[^;]+;`)
	reGenericDupKey  = regexp.MustCompile(`(?is)ON\s+DUPLICATE\s+KEY\s+UPDATE[^;]+;`)
)

// convertValuesToExcluded converts MySQL VALUES(col) references to SQLite excluded.col.
func convertValuesToExcluded(updateClause string) string {
	reValues := regexp.MustCompile(`(?i)VALUES\s*\(\s*(\w+)\s*\)`)
	return reValues.ReplaceAllString(updateClause, "excluded.$1")
}

var (
	// reAutoPK matches inline AUTO_INCREMENT PRIMARY KEY in various forms.
	reAutoPK        = regexp.MustCompile(`(?i)(?:BIGINT|INT|SMALLINT|MEDIUMINT|TINYINT)(?:\s+UNSIGNED)?(?:\s+NOT\s+NULL)?\s+AUTO_INCREMENT\s+(PRIMARY\s+KEY)`)
	reAutoPK2       = regexp.MustCompile(`(?i)(?:BIGINT|INT|SMALLINT|MEDIUMINT|TINYINT)\s+AUTO_INCREMENT\s+(PRIMARY\s+KEY)`)
	reAutoPKReversed = regexp.MustCompile(`(?i)(?:BIGINT|INT|SMALLINT|MEDIUMINT|TINYINT)(?:\s+UNSIGNED)?\s+(PRIMARY\s+KEY)\s+AUTO_INCREMENT`)
	reColName       = regexp.MustCompile(`^\s*\x60?(\w+)\x60?\s+`)
	reUnsigned      = regexp.MustCompile(`(?i)\s+UNSIGNED\b`)
	reAutoInc       = regexp.MustCompile(`(?i)\s+AUTO_INCREMENT\b`)
	reAlterStmt   = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(\x60?\w+\x60?)\s+(.*?);`)
	reAddUniqueKey = regexp.MustCompile(`(?i)ADD\s+UNIQUE\s+(?:KEY|INDEX)\s+(\x60?\w+\x60?)\s*\(([^)]+)\)`)
	reAddKey       = regexp.MustCompile(`(?i)ADD\s+(?:KEY|INDEX)\s+(\x60?\w+\x60?)\s*\(([^)]+)\)`)
	reDropKey      = regexp.MustCompile(`(?i)DROP\s+(?:KEY|INDEX)\s+(\x60?\w+\x60?)`)
	reAfterClause  = regexp.MustCompile(`(?i)\s+AFTER\s+\x60?\w+\x60?`)
)

// fixAutoIncrementPK converts MySQL AUTO_INCREMENT primary keys to SQLite INTEGER PRIMARY KEY
// and strips UNSIGNED from all column definitions.
func fixAutoIncrementPK(input string) string {
	// Inline: TYPE [UNSIGNED] [NOT NULL] AUTO_INCREMENT PRIMARY KEY.
	input = reAutoPK.ReplaceAllString(input, "INTEGER $1")
	input = reAutoPK2.ReplaceAllString(input, "INTEGER $1")
	// Reversed: TYPE [UNSIGNED] PRIMARY KEY AUTO_INCREMENT (some migrations swap order).
	input = reAutoPKReversed.ReplaceAllString(input, "INTEGER $1")
	// Table-level: col ... AUTO_INCREMENT + separate PRIMARY KEY (col) constraint.
	input = fixTableLevelAutoIncrementPK(input)
	input = reUnsigned.ReplaceAllString(input, "")
	input = reAutoInc.ReplaceAllString(input, "")
	return input
}

// fixTableLevelAutoIncrementPK handles CREATE TABLE blocks where a column has
// AUTO_INCREMENT but PRIMARY KEY is a separate table constraint.
// Converts `id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, ... PRIMARY KEY (id)`
// to `id INTEGER PRIMARY KEY, ...` (no separate PK constraint).
func fixTableLevelAutoIncrementPK(input string) string {
	return reCreateTable.ReplaceAllStringFunc(input, func(m string) string {
		sub := reCreateTable.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		body := sub[2]

		// Find any AUTO_INCREMENT column that does NOT have an inline PRIMARY KEY.
		lines := strings.Split(body, "\n")
		autoIncCol := ""
		for _, line := range lines {
			upper := strings.ToUpper(strings.TrimSpace(line))
			if !strings.Contains(upper, "AUTO_INCREMENT") || strings.Contains(upper, "PRIMARY KEY") {
				continue
			}
			if nm := reColName.FindStringSubmatch(line); nm != nil {
				autoIncCol = nm[1]
				break
			}
		}
		if autoIncCol == "" {
			return m
		}

		// Verify there is a separate PRIMARY KEY (col) constraint.
		reSepPK := regexp.MustCompile(`(?i)\bPRIMARY\s+KEY\s*\(\s*\x60?` + regexp.QuoteMeta(autoIncCol) + `\x60?\s*\)`)
		if !reSepPK.MatchString(m) {
			return m
		}

		// Rewrite the AUTO_INCREMENT column: TYPE ... AUTO_INCREMENT → INTEGER PRIMARY KEY.
		// Use ${1} not $1 to avoid Go treating "$1INTEGER" as group name "1INTEGER".
		reColDef := regexp.MustCompile(`(?i)\x60?` + regexp.QuoteMeta(autoIncCol) + `\x60?(\s+)(?:BIGINT|INT|SMALLINT|MEDIUMINT|TINYINT)(?:\s+UNSIGNED)?(?:\s+NOT\s+NULL|\s+NULL)?\s+AUTO_INCREMENT\b`)
		m = reColDef.ReplaceAllString(m, autoIncCol+"${1}INTEGER PRIMARY KEY")

		// Remove the now-redundant separate PRIMARY KEY (col) constraint. Take the
		// comma on exactly one side: eating both would splice the neighbouring
		// clauses together (a following CONSTRAINT then fails to parse).
		pk := `PRIMARY\s+KEY\s*\(\s*\x60?` + regexp.QuoteMeta(autoIncCol) + `\x60?\s*\)`
		if out := regexp.MustCompile(`(?i),\s*`+pk).ReplaceAllString(m, ""); out != m {
			return out
		}
		// No preceding clause - drop the trailing comma instead.
		return regexp.MustCompile(`(?i)`+pk+`\s*,\s*`).ReplaceAllString(m, "")
	})
}

// fixAlterTable rewrites MySQL ALTER TABLE statements for SQLite compatibility:
//   - splits multi-clause ADD COLUMN into individual statements
//   - strips AFTER col_name
//   - converts ADD [UNIQUE] KEY/INDEX to CREATE [UNIQUE] INDEX
//   - converts DROP KEY/INDEX to DROP INDEX
//   - skips MODIFY COLUMN / CHANGE (unsupported in SQLite)
func fixAlterTable(input string) string {
	return reAlterStmt.ReplaceAllStringFunc(input, func(m string) string {
		sub := reAlterStmt.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		tableName := strings.Trim(sub[1], "`")
		// Drop `--` comments first: a comment sitting between two clauses would
		// otherwise lead its clause and hide the ADD/DROP keyword behind it.
		body := reLineComment.ReplaceAllString(sub[2], "")

		clauses := splitAlterClauses(body)
		var stmts []string
		for _, clause := range clauses {
			clause = strings.TrimSpace(clause)
			upper := strings.ToUpper(clause)

			switch {
			case strings.HasPrefix(upper, "ADD UNIQUE KEY"), strings.HasPrefix(upper, "ADD UNIQUE INDEX"):
				idxM := reAddUniqueKey.FindStringSubmatch(clause)
				if idxM != nil {
					stmts = append(stmts, "CREATE UNIQUE INDEX IF NOT EXISTS "+
						strings.Trim(idxM[1], "`")+" ON "+tableName+"("+idxM[2]+");")
				}
			case strings.HasPrefix(upper, "ADD KEY"), strings.HasPrefix(upper, "ADD INDEX"):
				idxM := reAddKey.FindStringSubmatch(clause)
				if idxM != nil {
					stmts = append(stmts, "CREATE INDEX IF NOT EXISTS "+
						strings.Trim(idxM[1], "`")+" ON "+tableName+"("+idxM[2]+");")
				}
			case strings.HasPrefix(upper, "DROP KEY"), strings.HasPrefix(upper, "DROP INDEX"):
				idxM := reDropKey.FindStringSubmatch(clause)
				if idxM != nil {
					stmts = append(stmts, "DROP INDEX IF EXISTS "+strings.Trim(idxM[1], "`")+";")
				}
			case strings.HasPrefix(upper, "MODIFY"), strings.HasPrefix(upper, "CHANGE "):
				// No column type changes in SQLite. Harmless to skip: storage is
				// dynamically typed, so a VARCHAR widen/shrink is a no-op anyway.
				// Covers bare "MODIFY col ..." as well as "MODIFY COLUMN ...".
			case strings.HasPrefix(upper, "ADD CONSTRAINT"),
				strings.HasPrefix(upper, "DROP CONSTRAINT"),
				strings.HasPrefix(upper, "DROP FOREIGN KEY"),
				strings.HasPrefix(upper, "DROP CHECK"):
				// SQLite can't add or drop FK/CHECK constraints on an existing
				// table (needs a full rebuild), and it enforces no FKs here
				// anyway - the pool never sets PRAGMA foreign_keys=ON.
			case strings.HasPrefix(upper, "ADD COLUMN"), strings.HasPrefix(upper, "ADD ") && !strings.HasPrefix(upper, "ADD PRIMARY"):
				// Strip AFTER col_name and build individual ADD COLUMN.
				clause = reAfterClause.ReplaceAllString(clause, "")
				clause = reUnsigned.ReplaceAllString(clause, "")
				stmts = append(stmts, "ALTER TABLE "+tableName+" "+strings.TrimSpace(clause)+";")
			default:
				stmts = append(stmts, "ALTER TABLE "+tableName+" "+strings.TrimSpace(clause)+";")
			}
		}
		if len(stmts) == 0 {
			return ""
		}
		return strings.Join(stmts, "\n")
	})
}

// splitAlterClauses splits an ALTER TABLE body on top-level commas (not inside parens).
func splitAlterClauses(body string) []string {
	var clauses []string
	depth := 0
	start := 0
	for i, ch := range body {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				if clause := strings.TrimSpace(body[start:i]); clause != "" {
					clauses = append(clauses, clause)
				}
				start = i + 1
			}
		}
	}
	if last := strings.TrimSpace(body[start:]); last != "" {
		clauses = append(clauses, last)
	}
	return clauses
}
