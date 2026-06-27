package geoip

import (
	"net"
)

// asnRecord matches the GeoLite2-ASN mmdb structure.
type asnRecord struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// LookupASN returns the ASN number and organization for ip using the on-disk ASN DB.
// Returns ok=false when the DB is absent, the IP is missing, or no record exists.
func LookupASN(ip net.IP) (asn uint, org string, ok bool) {
	db, err := tryOpenMMDB(ASNDBPath)
	if err != nil {
		return 0, "", false
	}
	defer db.Close()
	var r asnRecord
	if err := db.Lookup(ip, &r); err != nil {
		return 0, "", false
	}
	if r.AutonomousSystemNumber == 0 {
		return 0, "", false
	}
	return r.AutonomousSystemNumber, r.AutonomousSystemOrganization, true
}
