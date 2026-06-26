package geoip

import "github.com/oschwald/maxminddb-golang"

// tryOpenMMDB opens the maxminddb file at path using the real mmdb reader.
// Separated from resolver.go so the maxminddb import is in one place.
func tryOpenMMDB(path string) (mmdbReader, error) {
	return maxminddb.Open(path)
}
