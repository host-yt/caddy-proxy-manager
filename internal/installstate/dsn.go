package installstate

import "fmt"

// BuildDSN constructs a go-sql-driver/mysql DSN from a DBState plus a
// plaintext password (caller decrypts the cipher).
func BuildDSN(db DBState, password string) string {
	tls := ""
	if db.TLS {
		tls = "&tls=true"
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC&charset=utf8mb4&multiStatements=true%s",
		db.User, password, db.Host, db.Port, db.Name, tls)
}

// BuildSQLiteDSN returns the modernc/sqlite DSN for the given file path.
func BuildSQLiteDSN(path string) string {
	if path == "" {
		path = "./data/hpg.db"
	}
	return "file:" + path + "?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000"
}
