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
