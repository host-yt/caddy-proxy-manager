// Package domain hosts business logic, grouped by aggregate.
//
// Subpackages own their entities and use-cases:
//   - users     — auth identities, roles, 2FA, recovery codes
//   - plans     — plan definitions and limit enforcement
//   - services  — VPS/service records (backend_ip is admin-only)
//   - routes    — domain→backend mappings, DNS+SSL lifecycle
//   - nodes     — Caddy node fleet, placement, health
//
// Handlers must call domain services, not repos directly.
package domain
