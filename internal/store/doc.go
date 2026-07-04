// Package store provides DB access. Concrete repos live in subpackages.
//
// Layout:
//   - internal/store/*.go — repository wrappers over database/sql.
//
// Migrations: goose, files in /migrations.
package store
