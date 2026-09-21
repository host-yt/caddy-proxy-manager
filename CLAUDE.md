# Project conventions

## Versioning

Semantic versioning, and the CHANGELOG section decides the bump - not gut feeling:

| The release's CHANGELOG contains | Bump |
|---|---|
| only `### Fixed` / `### Security` | patch (1.5.0 -> 1.5.1) |
| any `### Added` | minor (1.5.1 -> 1.6.0) |
| `### Upgrade notes` requiring manual operator work | minor; major if something that worked stops working |

Minor numbers are not decimals - 1.9.0 is followed by 1.10.0, and staying on
1.x indefinitely is correct. Reserve 2.0.0 for a break that forces every
operator to act: a config or API format change, a removed feature, an upgrade
that needs more than `docker pull`.

A released version is immutable. Tags, GitHub releases and GHCR image tags are
never renumbered or moved, because someone may have pinned them. History that
used the wrong bump stays as it is - 1.4.2, 1.4.3 and 1.4.9 shipped features as
patches, and that is not corrected retroactively.

## Release procedure

See the recipe in `docs/` and the CHANGELOG's own format
([Keep a Changelog](https://keepachangelog.com)). In short: land everything on
`main` with CI green, move `[Unreleased]` to the new version with a date,
commit, annotated tag, then `gh release create` from that CHANGELOG section.
