package backup

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"strings"
)

// DumpDatabase writes a logical dump (DDL + INSERTs) of the connected
// database to w. Format is MariaDB-compatible plain SQL, restorable via
// `mysql < dump.sql`. Foreign key checks are wrapped off-then-on so order
// of inserts doesn't matter.
//
// Pure-Go implementation: no mysqldump shellout (the distroless runtime
// image has no shell). Trade-off: slightly larger output than
// mysqldump --opt because we don't use extended-INSERT batching.
//
// Skips: goose's internal version table is included (so a restore stays
// consistent with the schema).
func DumpDatabase(ctx context.Context, db *sql.DB, w io.Writer) error {
	if db == nil {
		return fmt.Errorf("dump: nil db")
	}
	bw := bufio.NewWriterSize(w, 1<<16)
	defer bw.Flush()

	header := `-- Hostyt Proxy Gateway logical dump
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
SET UNIQUE_CHECKS = 0;
SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';

`
	if _, err := bw.WriteString(header); err != nil {
		return err
	}

	tables, err := listTables(ctx, db)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}

	for _, t := range tables {
		// DDL.
		if _, err := fmt.Fprintf(bw, "DROP TABLE IF EXISTS `%s`;\n", t); err != nil {
			return err
		}
		ddl, err := showCreate(ctx, db, t)
		if err != nil {
			return fmt.Errorf("show create %s: %w", t, err)
		}
		if _, err := bw.WriteString(ddl + ";\n\n"); err != nil {
			return err
		}
		// Data.
		if err := dumpRows(ctx, db, t, bw); err != nil {
			return fmt.Errorf("dump rows %s: %w", t, err)
		}
		if _, err := bw.WriteString("\n"); err != nil {
			return err
		}
	}

	footer := `SET FOREIGN_KEY_CHECKS = 1;
SET UNIQUE_CHECKS = 1;
`
	_, err = bw.WriteString(footer)
	return err
}

func listTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT TABLE_NAME FROM information_schema.tables
		 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
		 ORDER BY TABLE_NAME ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func showCreate(ctx context.Context, db *sql.DB, table string) (string, error) {
	row := db.QueryRowContext(ctx, fmt.Sprintf("SHOW CREATE TABLE `%s`", table))
	var name, ddl string
	if err := row.Scan(&name, &ddl); err != nil {
		return "", err
	}
	return ddl, nil
}

func dumpRows(ctx context.Context, db *sql.DB, table string, w io.Writer) error {
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
	colTypes, err := rows.ColumnTypes()
	if err != nil {
		return err
	}

	colList := "`" + strings.Join(cols, "`, `") + "`"
	row := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range row {
		ptrs[i] = &row[i]
	}

	first := true
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		if first {
			if _, err := fmt.Fprintf(w, "INSERT INTO `%s` (%s) VALUES\n", table, colList); err != nil {
				return err
			}
			first = false
		} else {
			if _, err := io.WriteString(w, ",\n"); err != nil {
				return err
			}
		}
		if err := writeRow(w, row, colTypes); err != nil {
			return err
		}
	}
	if !first {
		if _, err := io.WriteString(w, ";\n"); err != nil {
			return err
		}
	}
	return rows.Err()
}

func writeRow(w io.Writer, row []any, colTypes []*sql.ColumnType) error {
	if _, err := io.WriteString(w, "("); err != nil {
		return err
	}
	for i, v := range row {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := writeValue(w, v, colTypes[i]); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, ")")
	return err
}

func writeValue(w io.Writer, v any, ct *sql.ColumnType) error {
	if v == nil {
		_, err := io.WriteString(w, "NULL")
		return err
	}
	switch x := v.(type) {
	case []byte:
		// MySQL returns most non-numeric columns as []byte.
		return writeQuoted(w, string(x))
	case string:
		return writeQuoted(w, x)
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
		// Fallback: format and quote.
		return writeQuoted(w, fmt.Sprintf("%v", x))
	}
}

// writeQuoted emits a single-quoted SQL string with minimal escapes.
func writeQuoted(w io.Writer, s string) error {
	if _, err := io.WriteString(w, "'"); err != nil {
		return err
	}
	// Replace \ first to avoid double-escape.
	r := strings.NewReplacer(
		`\`, `\\`,
		`'`, `\'`,
		"\x00", `\0`,
		"\n", `\n`,
		"\r", `\r`,
		"\x1a", `\Z`,
	)
	if _, err := io.WriteString(w, r.Replace(s)); err != nil {
		return err
	}
	_, err := io.WriteString(w, "'")
	return err
}
