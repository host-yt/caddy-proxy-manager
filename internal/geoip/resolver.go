package geoip

import (
	"net"
	"os"
	"sync"
)

// Resolver looks up ISO alpha-2 country codes from IPv4/IPv6 addresses using
// the local GeoLite2-Country mmdb. Thread-safe; caches per-IP results to
// avoid repeated disk reads.
type Resolver struct {
	mu    sync.RWMutex
	cache map[string]string // ip string -> ISO2 code or ""
	db    mmdbReader
}

// mmdbReader is the subset of oschwald/maxminddb-golang we need, defined as
// an interface so the resolver compiles without the dependency when the DB is
// absent and tests can inject a stub.
type mmdbReader interface {
	Lookup(ip net.IP, result any) error
	Close() error
}

// geoRecord is the shape maxminddb decodes the GeoLite2-Country "country"
// record into. Only the IsoCode field is read.
type geoRecord struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

var (
	globalOnce     sync.Once
	globalResolver *Resolver
)

// Global returns the process-wide Resolver, opened lazily from DBPath.
// Returns a no-op resolver (all lookups return "") when the DB is absent or
// maxminddb is unavailable - the caller must never panic on a missing DB.
func Global() *Resolver {
	globalOnce.Do(func() {
		globalResolver = openResolver(DBPath)
	})
	return globalResolver
}

// ResetGlobal discards the cached global resolver so the next call to Global()
// re-opens the DB. Used after the GeoIP DB is refreshed on disk.
func ResetGlobal() {
	globalOnce = sync.Once{}
	globalResolver = nil
}

// openResolver attempts to open the mmdb at path. Falls back to a stub
// resolver that always returns "" when the file is absent or the maxminddb
// package is not linked in.
func openResolver(path string) *Resolver {
	if _, err := os.Stat(path); err != nil {
		// DB absent - return stub.
		return &Resolver{cache: make(map[string]string)}
	}
	r, err := tryOpenMMDB(path)
	if err != nil {
		return &Resolver{cache: make(map[string]string)}
	}
	return &Resolver{db: r, cache: make(map[string]string)}
}

// Available reports whether the underlying DB was successfully opened.
func (r *Resolver) Available() bool {
	return r != nil && r.db != nil
}

// LookupISO2 returns the ISO 3166-1 alpha-2 country code for ip, or "".
// Private / loopback / unspecified addresses always return "".
// Results are cached so repeated calls for the same IP are free.
func (r *Resolver) LookupISO2(ipStr string) string {
	if r == nil || r.db == nil {
		return ""
	}
	ip := net.ParseIP(ipStr)
	if ip == nil || isPrivateIP(ip) {
		return ""
	}

	// Fast path: cached result.
	r.mu.RLock()
	if code, ok := r.cache[ipStr]; ok {
		r.mu.RUnlock()
		return code
	}
	r.mu.RUnlock()

	var rec geoRecord
	if err := r.db.Lookup(ip, &rec); err != nil {
		r.set(ipStr, "")
		return ""
	}
	code := rec.Country.IsoCode
	r.set(ipStr, code)
	return code
}

func (r *Resolver) set(ip, code string) {
	r.mu.Lock()
	r.cache[ip] = code
	r.mu.Unlock()
}

// isPrivateIP checks RFC-1918, loopback, link-local, and ::1.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	ip4 := ip.To4()
	if ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}
	return false
}
