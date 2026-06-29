package store

import (
	"regexp"
	"strings"
)

// TransformForSQLite converts MySQL-dialect SQL to SQLite-compatible SQL.
// Used at migration time when the active driver is "sqlite3".
func TransformForSQLite(input string) string {
	// Handle stored procedures first (they wrap everything).
	if containsProcedure(input) {
		input = unwrapProcedures(input)
	}
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
	// ENUM(...) -> TEXT.
	input = reEnum.ReplaceAllString(input, "TEXT")
	// Remove any remaining information_schema references that slipped through.
	input = removeInfoSchemaBlocks(input)
	return input
}

var (
	reOnUpdate = regexp.MustCompile(`(?i)\s+ON\s+UPDATE\s+CURRENT_TIMESTAMP`)
	reEnum     = regexp.MustCompile(`(?i)ENUM\s*\([^)]+\)`)
)

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
	// inInfoGuard tracks whether we're inside an information_schema IF block.
	inInfoGuard := false
	// guardPastThen tracks whether we've seen THEN (and are now in the body).
	guardPastThen := false
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
				} else {
					result = append(result, line)
				}
				continue
			}
			// Multi-line information_schema IF guard handling.
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
					continue
				}
				// Keep the inner DDL (ALTER TABLE, etc.).
				if trimmed != "" {
					result = append(result, line)
				}
				continue
			}
			if isInfoSchemaIf(upper) {
				inInfoGuard = true
				guardPastThen = strings.HasSuffix(upper, "THEN")
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

// isInfoSchemaIf returns true if the line starts an information_schema IF block.
func isInfoSchemaIf(upper string) bool {
	return strings.Contains(upper, "INFORMATION_SCHEMA") &&
		(strings.HasPrefix(upper, "IF NOT EXISTS") || strings.HasPrefix(upper, "IF EXISTS"))
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

// reInlineIndex matches MySQL inline index lines in CREATE TABLE.
var (
	reUniqueKey = regexp.MustCompile("(?i),?\\s*(UNIQUE\\s+KEY\\s+(\\S+)\\s*\\(([^)]+)\\))")
	reKey       = regexp.MustCompile("(?i),?\\s*((?:KEY|INDEX)\\s+(\\S+)\\s*\\(([^)]+)\\))")
)

func transformCreateTable(stmt string) string {
	// Extract table name for CREATE INDEX statements.
	tableNameRe := regexp.MustCompile("(?i)CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?[`\"]?(\\w+)[`\"]?\\s*\\(")
	nameMatch := tableNameRe.FindStringSubmatch(stmt)
	if nameMatch == nil {
		return stmt
	}
	tableName := nameMatch[1]

	var extraIndexes []string

	// Remove UNIQUE KEY lines and collect them.
	stmt = reUniqueKey.ReplaceAllStringFunc(stmt, func(m string) string {
		sub := reUniqueKey.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		idxName := strings.Trim(sub[2], "`\"")
		cols := sub[3]
		extraIndexes = append(extraIndexes,
			"CREATE UNIQUE INDEX IF NOT EXISTS "+idxName+" ON "+tableName+"("+cols+");")
		return ""
	})

	// Remove KEY/INDEX lines and collect them.
	stmt = reKey.ReplaceAllStringFunc(stmt, func(m string) string {
		sub := reKey.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		idxName := strings.Trim(sub[2], "`\"")
		cols := sub[3]
		extraIndexes = append(extraIndexes,
			"CREATE INDEX IF NOT EXISTS "+idxName+" ON "+tableName+"("+cols+");")
		return ""
	})

	if len(extraIndexes) == 0 {
		return stmt
	}
	// Append CREATE INDEX statements after the CREATE TABLE.
	return stmt + "\n" + strings.Join(extraIndexes, "\n")
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
	// reAutoPK matches MySQL integer PK columns with AUTO_INCREMENT.
	reAutoPK = regexp.MustCompile(`(?i)(?:BIGINT|INT|SMALLINT|MEDIUMINT|TINYINT)\s+UNSIGNED\s+AUTO_INCREMENT\s+(PRIMARY\s+KEY)`)
	reAutoPK2 = regexp.MustCompile(`(?i)(?:BIGINT|INT|SMALLINT|MEDIUMINT|TINYINT)\s+AUTO_INCREMENT\s+(PRIMARY\s+KEY)`)
	reUnsigned    = regexp.MustCompile(`(?i)\s+UNSIGNED\b`)
	reAutoInc     = regexp.MustCompile(`(?i)\s+AUTO_INCREMENT\b`)
	reAlterStmt   = regexp.MustCompile(`(?is)ALTER\s+TABLE\s+(\x60?\w+\x60?)\s+(.*?);`)
	reAddUniqueKey = regexp.MustCompile(`(?i)ADD\s+UNIQUE\s+(?:KEY|INDEX)\s+(\x60?\w+\x60?)\s*\(([^)]+)\)`)
	reAddKey       = regexp.MustCompile(`(?i)ADD\s+(?:KEY|INDEX)\s+(\x60?\w+\x60?)\s*\(([^)]+)\)`)
	reDropKey      = regexp.MustCompile(`(?i)DROP\s+(?:KEY|INDEX)\s+(\x60?\w+\x60?)`)
	reAfterClause  = regexp.MustCompile(`(?i)\s+AFTER\s+\x60?\w+\x60?`)
)

// fixAutoIncrementPK converts MySQL AUTO_INCREMENT primary keys to SQLite INTEGER PRIMARY KEY
// and strips UNSIGNED from all column definitions.
func fixAutoIncrementPK(input string) string {
	input = reAutoPK.ReplaceAllString(input, "INTEGER $1")
	input = reAutoPK2.ReplaceAllString(input, "INTEGER $1")
	input = reUnsigned.ReplaceAllString(input, "")
	input = reAutoInc.ReplaceAllString(input, "")
	return input
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
		body := sub[2]

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
			case strings.HasPrefix(upper, "MODIFY COLUMN"), strings.HasPrefix(upper, "CHANGE "):
				// SQLite does not support column type changes - skip.
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
