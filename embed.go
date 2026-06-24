// Package proxygateway exposes embedded assets (migrations, etc.) that live
// at the repository root and must be reachable from cmd/server.
package proxygateway

import "embed"

// MigrationsFS contains every goose migration file under migrations/.
// Consumed by internal/store.RunMigrations.
//
//go:embed all:migrations
var MigrationsFS embed.FS

// ScriptsFS holds installable shell scripts served from the panel
// (e.g. /install/node.sh for one-command node join).
//
//go:embed scripts/node-join.sh
var ScriptsFS embed.FS

// StaticFS embeds the entire web/static tree so the binary is self-contained
// and serves /static/* regardless of the working directory it's launched from.
// tailwind.css is only present here when it was built before `go build` (the
// Dockerfile/Makefile build CSS first); when absent the server falls back to
// reading web/static from disk.
//
//go:embed all:web/static
var StaticFS embed.FS
