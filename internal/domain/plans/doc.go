package plans

// Plan limits enforced at: route create, port add, service create.
// SSL toggle gates Caddy On-Demand; path routing gates non-root path matches;
// wildcard domains gated by plan flag (DNS-01 required, not in MVP).
