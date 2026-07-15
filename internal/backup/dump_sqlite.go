package backup

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// dumpSQLite writes a logical dump of a SQLite database: DDL straight from
// sqlite_master plus INSERTs. Restorable by executing the statements against a
// fresh SQLite file (see SplitSQLStatements). The MySQL dump path cannot be
// shared: SQLite has no information_schema/SHOW CREATE, and its string
// literals escape quotes by doubling - backslash escapes would be stored
// verbatim.
func dumpSQLite(ctx context.Context, db *sql.DB, w io.Writer) error {
	bw := bufio.NewWriterSize(w, 1<<16)
	defer bw.Flush()

	if _, err := bw.WriteString("-- Hostyt Proxy Gateway logical dump (sqlite)\nPRAGMA foreign_keys=OFF;\n\n"); err != nil {
		return err
	}

	type object struct{ name, ddl string }
	listObjects := func(typ string) ([]object, error) {
		rows, err := db.QueryContext(ctx,
			`SELECT name, sql FROM sqlite_master
			 WHERE type = ? AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL
			 ORDER BY name ASC`, typ)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []object
		for rows.Next() {
			var o object
			if err := rows.Scan(&o.name, &o.ddl); err != nil {
				return nil, err
			}
			if !validIdentifier(o.name) {
				continue // same backtick-injection guard as the MySQL path
			}
			out = append(out, o)
		}
		return out, rows.Err()
	}

	tables, err := listObjects("table")
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	for _, t := range tables {
		if _, err := fmt.Fprintf(bw, "DROP TABLE IF EXISTS `%s`;\n%s;\n\n", t.name, t.ddl); err != nil {
			return err
		}
		if err := dumpRowsSQLite(ctx, db, t.name, bw); err != nil {
			return fmt.Errorf("dump rows %s: %w", t.name, err)
		}
	}

	// Secondary indexes (auto-indexes carry sql IS NULL and are filtered out).
	indexes, err := listObjects("index")
	if err != nil {
		return fmt.Errorf("list indexes: %w", err)
	}
	for _, ix := range indexes {
		if _, err := fmt.Fprintf(bw, "%s;\n", ix.ddl); err != nil {
			return err
		}
	}

	_, err = bw.WriteString("\nPRAGMA foreign_keys=ON;\n")
	return err
}

func dumpRowsSQLite(ctx context.Context, db *sql.DB, table string, w io.Writer) error {
	rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM `%s`", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	if len(cols) == 0 {
		return nil
	}
	colList := "`" + strings.Join(cols, "`, `") + "`"
	row := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range row {
		ptrs[i] = &row[i]
	}

	wrote := false
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		// One INSERT per row: multi-row VALUES would only complicate the
		// splitter and drill restore for no meaningful size win at this scale.
		if _, err := fmt.Fprintf(w, "INSERT INTO `%s` (%s) VALUES (", table, colList); err != nil {
			return err
		}
		for i, v := range row {
			if i > 0 {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			if err := writeValueSQLite(w, v); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, ");\n"); err != nil {
			return err
		}
		wrote = true
	}
	if wrote {
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	return rows.Err()
}

func writeValueSQLite(w io.Writer, v any) error {
	switch x := v.(type) {
	case nil:
		_, err := io.WriteString(w, "NULL")
		return err
	case []byte:
		// Blob literal: type-faithful, and sidesteps quoting entirely.
		_, err := io.WriteString(w, "X'"+hex.EncodeToString(x)+"'")
		return err
	case string:
		// SQLite escapes a quote by doubling it; there are no backslash
		// escapes, and raw newlines inside the literal are legal.
		_, err := io.WriteString(w, "'"+strings.ReplaceAll(x, "'", "''")+"'")
		return err
	case int64:
		_, err := fmt.Fprintf(w, "%d", x)
		return err
	case float64:
		_, err := fmt.Fprintf(w, "%g", x)
		return err
	case bool:
		if x {
			_, err := io.WriteString(w, "1")
			return err
		}
		_, err := io.WriteString(w, "0")
		return err
	default:
		_, err := io.WriteString(w, "'"+strings.ReplaceAll(fmt.Sprintf("%v", x), "'", "''")+"'")
		return err
	}
}

// SplitSQLStatements splits a SQLite dump into executable statements. Naive
// splitting on ";" breaks on values containing semicolons or newlines, so this
// walks the text tracking single-quoted literals (with '' doubling) and `--`
// comments. Exported for the restore drill.
func SplitSQLStatements(dump string) []string {
	var (
		out     []string
		start   = 0
		inQuote = false
	)
	for i := 0; i < len(dump); i++ {
		c := dump[i]
		if inQuote {
			if c == '\'' {
				if i+1 < len(dump) && dump[i+1] == '\'' {
					i++ // escaped quote
					continue
				}
				inQuote = false
			}
			continue
		}
		switch c {
		case '\'':
			inQuote = true
		case '-':
			if i+1 < len(dump) && dump[i+1] == '-' {
				// comment runs to end of line
				for i < len(dump) && dump[i] != '\n' {
					i++
				}
			}
		case ';':
			if stmt := strings.TrimSpace(dump[start:i]); stmt != "" {
				out = append(out, stmt)
			}
			start = i + 1
		}
	}
	if stmt := strings.TrimSpace(dump[start:]); stmt != "" {
		out = append(out, stmt)
	}
	return out
}
