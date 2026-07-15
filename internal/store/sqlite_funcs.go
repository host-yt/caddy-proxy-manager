package store

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"time"

	sqlite3 "modernc.org/sqlite"
)

// The runtime queries are written in MySQL's dialect. Rather than rewrite every
// call site, teach SQLite the handful of MySQL functions they lean on - the
// registration is global and applies to every connection opened afterwards.
// This covers functions only; MySQL *syntax* (INTERVAL arithmetic, ON DUPLICATE
// KEY UPDATE, FOR UPDATE) still needs the dialect helpers in driver.go.
func init() {
	// NOW()/UTC_TIMESTAMP(): SQLite's CURRENT_TIMESTAMP is UTC, and so is the
	// panel's clock, so both sides of an "expires_at > NOW()" compare agree.
	sqlite3.MustRegisterScalarFunction("NOW", 0, func(_ *sqlite3.FunctionContext, _ []driver.Value) (driver.Value, error) {
		return time.Now().UTC().Format("2006-01-02 15:04:05"), nil
	})
	sqlite3.MustRegisterScalarFunction("UTC_TIMESTAMP", 0, func(_ *sqlite3.FunctionContext, _ []driver.Value) (driver.Value, error) {
		return time.Now().UTC().Format("2006-01-02 15:04:05"), nil
	})
	// GREATEST/LEAST: SQLite spells them max()/min(), but only when variadic -
	// the aggregate of the same name shadows the scalar for a single argument.
	sqlite3.MustRegisterScalarFunction("GREATEST", -1, func(_ *sqlite3.FunctionContext, args []driver.Value) (driver.Value, error) {
		return pickExtreme(args, true)
	})
	sqlite3.MustRegisterScalarFunction("LEAST", -1, func(_ *sqlite3.FunctionContext, args []driver.Value) (driver.Value, error) {
		return pickExtreme(args, false)
	})
	sqlite3.MustRegisterScalarFunction("DATE_FORMAT", 2, dateFormat)
	sqlite3.MustRegisterScalarFunction("DATEDIFF", 2, dateDiff)
	sqlite3.MustRegisterScalarFunction("TIMESTAMPDIFF", 3, timestampDiff)
	sqlite3.MustRegisterScalarFunction("UNIX_TIMESTAMP", 1, unixTimestamp)
	sqlite3.MustRegisterScalarFunction("LEFT", 2, leftFunc)
	sqlite3.MustRegisterScalarFunction("LOCATE", 2, locateFunc)
	sqlite3.MustRegisterScalarFunction("SUBSTRING_INDEX", 3, substringIndex)
	// CONCAT, GROUP_CONCAT, IF and IFNULL already resolve natively, and integer
	// division is what "/" does on integers here, so MySQL's DIV needs no
	// function - see IntDiv in driver.go.
}

// unixTimestamp implements MySQL's UNIX_TIMESTAMP(value) - epoch seconds.
func unixTimestamp(_ *sqlite3.FunctionContext, args []driver.Value) (driver.Value, error) {
	if args[0] == nil {
		return nil, nil
	}
	t, err := parseSQLiteTime(args[0])
	if err != nil {
		return nil, nil
	}
	return t.Unix(), nil
}

// leftFunc implements MySQL's LEFT(str, n) - the first n characters.
func leftFunc(_ *sqlite3.FunctionContext, args []driver.Value) (driver.Value, error) {
	s, n, ok := strAndInt(args)
	if !ok {
		return nil, nil
	}
	if n <= 0 {
		return "", nil
	}
	r := []rune(s)
	if int(n) >= len(r) {
		return s, nil
	}
	return string(r[:n]), nil
}

// locateFunc implements MySQL's LOCATE(needle, haystack): the 1-based position
// of needle, or 0 when absent.
func locateFunc(_ *sqlite3.FunctionContext, args []driver.Value) (driver.Value, error) {
	needle, ok1 := args[0].(string)
	hay, ok2 := args[1].(string)
	if !ok1 || !ok2 {
		return nil, nil
	}
	i := strings.Index(hay, needle)
	if i < 0 {
		return int64(0), nil
	}
	// MySQL counts characters, not bytes.
	return int64(len([]rune(hay[:i]))) + 1, nil
}

// substringIndex implements MySQL's SUBSTRING_INDEX(str, delim, count) for a
// positive count: everything before the count-th delimiter.
func substringIndex(_ *sqlite3.FunctionContext, args []driver.Value) (driver.Value, error) {
	s, ok1 := args[0].(string)
	delim, ok2 := args[1].(string)
	count, ok3 := toInt(args[2])
	if !ok1 || !ok2 || !ok3 || delim == "" {
		return nil, nil
	}
	if count > 0 {
		parts := strings.Split(s, delim)
		if int(count) >= len(parts) {
			return s, nil
		}
		return strings.Join(parts[:count], delim), nil
	}
	parts := strings.Split(s, delim)
	if n := int(-count); n < len(parts) {
		return strings.Join(parts[len(parts)-n:], delim), nil
	}
	return s, nil
}

func strAndInt(args []driver.Value) (string, int64, bool) {
	s, ok := args[0].(string)
	if !ok {
		return "", 0, false
	}
	n, ok := toInt(args[1])
	return s, n, ok
}

func toInt(v driver.Value) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case float64:
		return int64(n), true
	}
	return 0, false
}

// dateDiff implements MySQL's DATEDIFF(a, b) - whole days between two dates,
// counted from the calendar date only.
func dateDiff(_ *sqlite3.FunctionContext, args []driver.Value) (driver.Value, error) {
	a, b, ok, err := twoTimes(args[0], args[1])
	if !ok || err != nil {
		return nil, nil
	}
	ad := time.Date(a.Year(), a.Month(), a.Day(), 0, 0, 0, 0, time.UTC)
	bd := time.Date(b.Year(), b.Month(), b.Day(), 0, 0, 0, 0, time.UTC)
	return int64(ad.Sub(bd).Hours() / 24), nil
}

// timestampDiff implements MySQL's TIMESTAMPDIFF(unit, a, b): b - a, in unit.
func timestampDiff(_ *sqlite3.FunctionContext, args []driver.Value) (driver.Value, error) {
	unit, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("TIMESTAMPDIFF: unit must be a string, got %T", args[0])
	}
	a, b, ok, err := twoTimes(args[1], args[2])
	if !ok || err != nil {
		return nil, nil
	}
	d := b.Sub(a)
	switch strings.ToUpper(unit) {
	case "SECOND":
		return int64(d.Seconds()), nil
	case "MINUTE":
		return int64(d.Minutes()), nil
	case "HOUR":
		return int64(d.Hours()), nil
	case "DAY":
		return int64(d.Hours() / 24), nil
	}
	return nil, fmt.Errorf("TIMESTAMPDIFF: unsupported unit %q", unit)
}

// twoTimes parses a pair of arguments, reporting ok=false when either is NULL.
func twoTimes(x, y driver.Value) (a, b time.Time, ok bool, err error) {
	if x == nil || y == nil {
		return a, b, false, nil
	}
	if a, err = parseSQLiteTime(x); err != nil {
		return a, b, false, err
	}
	if b, err = parseSQLiteTime(y); err != nil {
		return a, b, false, err
	}
	return a, b, true, nil
}

// mysqlToGoLayout maps the MySQL DATE_FORMAT specifiers the queries actually
// use onto Go reference-time layouts.
var mysqlToGoLayout = strings.NewReplacer(
	"%Y", "2006", "%m", "01", "%d", "02",
	"%H", "15", "%i", "04", "%s", "05",
	"%f", "000000",
)

// dateFormat implements MySQL's DATE_FORMAT(value, format) for SQLite. NULL in,
// NULL out - the queries wrap it in COALESCE and expect that.
func dateFormat(_ *sqlite3.FunctionContext, args []driver.Value) (driver.Value, error) {
	if len(args) != 2 || args[0] == nil {
		return nil, nil
	}
	format, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("DATE_FORMAT: format must be a string, got %T", args[1])
	}
	t, err := parseSQLiteTime(args[0])
	if err != nil {
		return nil, nil
	}
	return t.Format(mysqlToGoLayout.Replace(format)), nil
}

// parseSQLiteTime accepts the shapes a timestamp column can come back as.
func parseSQLiteTime(v driver.Value) (time.Time, error) {
	switch x := v.(type) {
	case time.Time:
		return x, nil
	case string:
		for _, layout := range []string{
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05Z07:00",
			"2006-01-02",
		} {
			if t, err := time.Parse(layout, x); err == nil {
				return t, nil
			}
		}
		return time.Time{}, fmt.Errorf("unrecognised time %q", x)
	case int64:
		return time.Unix(x, 0).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unsupported time type %T", v)
}

// pickExtreme returns the largest (or smallest) argument. MySQL returns NULL if
// any argument is NULL; callers rely on that to make COALESCE explicit.
func pickExtreme(args []driver.Value, greatest bool) (driver.Value, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("GREATEST/LEAST: no arguments")
	}
	var best driver.Value
	for _, a := range args {
		if a == nil {
			return nil, nil
		}
		if best == nil {
			best = a
			continue
		}
		cmp, err := compareValues(a, best)
		if err != nil {
			return nil, err
		}
		if (greatest && cmp > 0) || (!greatest && cmp < 0) {
			best = a
		}
	}
	return best, nil
}

// compareValues orders two SQLite values: numerically when both are numeric,
// lexically otherwise (which keeps 'YYYY-MM-DD HH:MM:SS' timestamps ordered).
func compareValues(a, b driver.Value) (int, error) {
	af, aNum := toFloat(a)
	bf, bNum := toFloat(b)
	if aNum && bNum {
		switch {
		case af > bf:
			return 1, nil
		case af < bf:
			return -1, nil
		default:
			return 0, nil
		}
	}
	as, bs := fmt.Sprint(a), fmt.Sprint(b)
	switch {
	case as > bs:
		return 1, nil
	case as < bs:
		return -1, nil
	default:
		return 0, nil
	}
}

func toFloat(v driver.Value) (float64, bool) {
	switch n := v.(type) {
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}
