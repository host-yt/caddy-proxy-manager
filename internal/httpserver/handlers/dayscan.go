package handlers

import "time"

// scanDayKey normalises a SQL DATE() result to "2006-01-02". MySQL with
// parseTime=true yields time.Time, SQLite yields TEXT - scanning either into
// the other's Go type silently drops every bucket.
func scanDayKey(v any) (string, bool) {
	switch d := v.(type) {
	case time.Time:
		return d.Format("2006-01-02"), true
	case []byte:
		return dayPrefix(string(d))
	case string:
		return dayPrefix(d)
	}
	return "", false
}

func dayPrefix(s string) (string, bool) {
	if len(s) < 10 {
		return "", false
	}
	if _, err := time.Parse("2006-01-02", s[:10]); err != nil {
		return "", false
	}
	return s[:10], true
}
