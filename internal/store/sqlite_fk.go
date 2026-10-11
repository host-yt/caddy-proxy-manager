package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
)

// purgeSQLiteOrphans resolves rows left dangling while SQLite FKs were not
// enforced, applying the ON DELETE action the parent delete would have fired.
// RESTRICT/NO ACTION orphans are only logged: deleting live config is worse.
func purgeSQLiteOrphans(ctx context.Context, db *sql.DB) error {
	// A cascade delete can orphan grandchildren; repeat until stable.
	for pass := 0; pass < 10; pass++ {
		type orphan struct {
			table, parent string
			rowid         sql.NullInt64
			fkid          int
		}
		rows, err := db.QueryContext(ctx, "PRAGMA foreign_key_check")
		if err != nil {
			return fmt.Errorf("foreign_key_check: %w", err)
		}
		var found []orphan
		for rows.Next() {
			var o orphan
			if err := rows.Scan(&o.table, &o.rowid, &o.parent, &o.fkid); err != nil {
				rows.Close()
				return fmt.Errorf("foreign_key_check scan: %w", err)
			}
			found = append(found, o)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("foreign_key_check: %w", err)
		}

		fixed := 0
		for _, o := range found {
			cols, action, err := sqliteFKAction(ctx, db, o.table, o.fkid)
			if err != nil {
				return err
			}
			if !o.rowid.Valid || (action != "CASCADE" && action != "SET NULL") {
				if pass == 0 {
					slog.Warn("sqlite: orphan row left in place", "table", o.table, "rowid", o.rowid.Int64, "parent", o.parent, "on_delete", action)
				}
				continue
			}
			q := `DELETE FROM "` + o.table + `" WHERE rowid = ?`
			if action == "SET NULL" {
				set := make([]string, len(cols))
				for i, c := range cols {
					set[i] = `"` + c + `" = NULL`
				}
				q = `UPDATE "` + o.table + `" SET ` + strings.Join(set, ", ") + ` WHERE rowid = ?`
			}
			if _, err := db.ExecContext(ctx, q, o.rowid.Int64); err != nil {
				return fmt.Errorf("purge orphan %s rowid %d: %w", o.table, o.rowid.Int64, err)
			}
			slog.Warn("sqlite: purged orphan row", "table", o.table, "rowid", o.rowid.Int64, "parent", o.parent, "on_delete", action)
			fixed++
		}
		if fixed == 0 {
			return nil
		}
	}
	return nil
}

// sqliteFKAction returns the child columns and ON DELETE action of FK id on table.
func sqliteFKAction(ctx context.Context, db *sql.DB, table string, id int) ([]string, string, error) {
	rows, err := db.QueryContext(ctx, `SELECT "from", on_delete FROM pragma_foreign_key_list(?) WHERE id = ?`, table, id)
	if err != nil {
		return nil, "", fmt.Errorf("foreign_key_list %s: %w", table, err)
	}
	defer rows.Close()
	var cols []string
	var action string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c, &action); err != nil {
			return nil, "", err
		}
		cols = append(cols, c)
	}
	return cols, action, rows.Err()
}

// sqliteMigrationFKBracket turns FK enforcement off for a migration run
// (table drops would otherwise fire cascades) and returns the closer that
// purges orphans and restores the previous setting.
func sqliteMigrationFKBracket(ctx context.Context, db *sql.DB) (func() error, error) {
	var was int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&was); err != nil {
		return nil, fmt.Errorf("read foreign_keys: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return nil, fmt.Errorf("disable foreign_keys: %w", err)
	}
	return func() error {
		err := purgeSQLiteOrphans(ctx, db)
		if was == 1 {
			if _, e := db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); e != nil && err == nil {
				err = fmt.Errorf("enable foreign_keys: %w", e)
			}
		}
		return err
	}, nil
}
