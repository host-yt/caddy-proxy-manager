// Package buildinfo carries the release version stamped at link time.
package buildinfo

// Version is set via -ldflags "-X .../internal/buildinfo.Version=..."; "dev" for local builds.
var Version = "dev"
