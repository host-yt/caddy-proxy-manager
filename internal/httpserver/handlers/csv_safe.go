package handlers

// csvSafe neutralizes spreadsheet formula injection: a cell beginning with
// =, +, -, @ (or a tab/CR that some apps strip to expose those) is executed as
// a formula by Excel/Sheets. Prefix such values with a single quote.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// csvSafeRow applies csvSafe to every field in place, then returns the slice.
func csvSafeRow(row []string) []string {
	for i := range row {
		row[i] = csvSafe(row[i])
	}
	return row
}
