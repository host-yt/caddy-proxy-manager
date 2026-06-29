package installstate

import "fmt"

// BuildDSN constructs a go-sql-driver/mysql DSN from a DBState plus a
// plaintext password (caller decrypts the cipher).
func BuildDSN(db DBState, password string) string {
	tls := ""
	if db.TLS {
		tls = "&tls=true"
	}
	// time_zone='+00:00' pins the session to UTC so UNIX_TIMESTAMP()/NOW() agree
	// with the UTC values Go writes (loc=UTC). Without it, time-bucketed queries
	// (traffic trend, error-rate series) compute keys in the server's local TZ
	// and never match Go's UTC bucket keys -> empty/zeroed charts.
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC&time_zone=%%27%%2B00%%3A00%%27&charset=utf8mb4&multiStatements=true%s",
		db.User, password, db.Host, db.Port, db.Name, tls)
}

// BuildSQLiteDSN returns the modernc/sqlite DSN for the given file path.
func BuildSQLiteDSN(path string) string {
	if path == "" {
		path = "./data/hpg.db"
	}
	return "file:" + path + "?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000"
}
