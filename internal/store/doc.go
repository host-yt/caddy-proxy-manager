// Package store provides DB access. Concrete repos live in subpackages.
//
// Layout:
//   - internal/store/db   — sqlc-generated typed queries
//   - internal/store/*.go — repository wrappers exposing domain-friendly APIs
//
// Migrations: goose, files in /migrations.
package store
