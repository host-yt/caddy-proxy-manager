package backup

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// dumpTimeout bounds how long a dump may hold its snapshot transaction open.
// MySQL keeps undo log entries and SQLite keeps WAL pages alive for the
// whole transaction, so a stuck or oversized dump must not hold it forever
// (HPG-012).
const dumpTimeout = 15 * time.Minute

// queryer is satisfied by both *sql.DB and *sql.Conn. Dump functions take it
// pinned to a single *sql.Conn so every query in the dump runs against the
// same connection - and therefore the same transaction snapshot.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

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
//
// The whole dump runs inside one read-only snapshot transaction on a single
// connection (HPG-012): without it, each table is read independently and a
// concurrent write between two of those reads can leave the archive with a
// combination of rows that never coexisted in the live database (orphaned
// relations across tables even though every individual SELECT succeeded).
func DumpDatabase(ctx context.Context, db *sql.DB, w io.Writer) error {
	if db == nil {
		return fmt.Errorf("dump: nil db")
	}
	ctx, cancel := context.WithTimeout(ctx, dumpTimeout)
	defer cancel()

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("dump: acquire connection: %w", err)
	}
	defer conn.Close()

	if store.Driver() == "sqlite3" {
		// Different introspection AND different string escaping - see dump_sqlite.go.
		return dumpSQLite(ctx, conn, w)
	}
	return dumpMySQL(ctx, conn, w)
}

func dumpMySQL(ctx context.Context, conn *sql.Conn, w io.Writer) (err error) {
	if _, serr := conn.ExecContext(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"); serr != nil {
		return fmt.Errorf("dump: set isolation: %w", serr)
	}
	if _, serr := conn.ExecContext(ctx, "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY"); serr != nil {
		return fmt.Errorf("dump: start snapshot: %w", serr)
	}
	// Read-only: nothing to commit, and rolling back releases the snapshot
	// promptly instead of leaving it to connection-close cleanup.
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()

	bw := bufio.NewWriterSize(w, 1<<16)
	defer func() {
		// A flush error (e.g. disk full) must surface even though every
		// individual buffered Write above it looked fine (HPG-013).
		if ferr := bw.Flush(); err == nil {
			err = ferr
		}
	}()

	header := `-- Hostyt Proxy Gateway logical dump
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
SET UNIQUE_CHECKS = 0;
SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';

`
	if _, werr := bw.WriteString(header); werr != nil {
		return werr
	}

	tables, terr := listTables(ctx, conn)
	if terr != nil {
		return fmt.Errorf("list tables: %w", terr)
	}

	for _, t := range tables {
		// DDL.
		if _, werr := fmt.Fprintf(bw, "DROP TABLE IF EXISTS `%s`;\n", t); werr != nil {
			return werr
		}
		ddl, cerr := showCreate(ctx, conn, t)
		if cerr != nil {
			return fmt.Errorf("show create %s: %w", t, cerr)
		}
		if _, werr := bw.WriteString(ddl + ";\n\n"); werr != nil {
			return werr
		}
		// Data.
		if rerr := dumpRows(ctx, conn, t, bw); rerr != nil {
			return fmt.Errorf("dump rows %s: %w", t, rerr)
		}
		if _, werr := bw.WriteString("\n"); werr != nil {
			return werr
		}
	}

	footer := `SET FOREIGN_KEY_CHECKS = 1;
SET UNIQUE_CHECKS = 1;
`
	_, err = bw.WriteString(footer)
	return err
}

// validIdentifier ensures table names contain only [A-Za-z0-9_].
// Names come from information_schema but a backtick inside a name would break
// the backtick-quoted fmt.Sprintf interpolations below (second-order injection).
func validIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

func listTables(ctx context.Context, db queryer) ([]string, error) {
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
		if !validIdentifier(t) {
			continue // skip tables with non-identifier names (backtick injection guard)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func showCreate(ctx context.Context, db queryer, table string) (string, error) {
	if !validIdentifier(table) {
		return "", fmt.Errorf("invalid table name: %q", table)
	}
	row := db.QueryRowContext(ctx, fmt.Sprintf("SHOW CREATE TABLE `%s`", table))
	var name, ddl string
	if err := row.Scan(&name, &ddl); err != nil {
		return "", err
	}
	return ddl, nil
}

func dumpRows(ctx context.Context, db queryer, table string, w io.Writer) error {
	if !validIdentifier(table) {
		return fmt.Errorf("invalid table name: %q", table)
	}
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
