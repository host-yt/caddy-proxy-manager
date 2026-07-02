# Contributing

Thanks for considering a patch. This document is the short version of
how the project is built - read it once, then go.

## Tooling

- Go **1.26+** (matches `go.mod`)
- Docker + Docker Compose v2
- Optional: `make`, `templ`, `sqlc`, `goose`, `golangci-lint` -
  installable in one go with `make tools`.

## Local development loop

```bash
cp .env.example .env                       # fill APP_SECRET (openssl rand -hex 32)
docker compose -f deploy/docker-compose.yml --env-file .env up -d mariadb redis caddy
APP_URL=http://localhost:8080 APP_SECRET=… go run ./cmd/server
# or with hot reload (install air via `make tools`):
make dev
```

Wizard at `http://localhost:8080/install` walks through DB connection,
admin user, panel URL, SMTP, first Caddy node.

## Style

- `go fmt ./...`, `go vet ./...`, and `golangci-lint run` must pass.
- Keep imports grouped: stdlib / third-party / project.
- No `panic` in request paths. Use `Recoverer` middleware for the
  defense-in-depth catch.
- Comments explain the **why**, not the **what**.
- Errors wrapped with `fmt.Errorf("doing X: %w", err)`.

## Architecture rules

- **Handlers** parse + render. No business logic, no SQL.
- **Domain packages** (`internal/domain/*`) own invariants and call
  repos.
- **Repos / sqlc** run SQL, return dumb rows.
- **`installstate.Manager`** is the only place that touches at-rest
  crypto (HKDF-derived AES-256-GCM keys); use it for any new secret
  you persist.

## Adding things

See [`docs/SPEC.md`](docs/SPEC.md) for the functional spec: Overview,
Roles, Core Entities, Auth Flows, Caddy Integration, WireGuard Tunnels,
L4 Streams, AI Assistant, Analytics.

## Tests

Unit + integration tests live next to the code under test. The
integration tier requires a live MariaDB and Redis - point them via
env when running `go test`.

```bash
make test          # race detector on by default
make cover         # writes coverage.txt + summary
```

## Commit style

Conventional Commits prefixes: `feat(...)`, `fix(...)`, `chore(...)`,
`docs(...)`, `refactor(...)`. Keep the subject under 72 chars; explain
the **why** in the body when it isn't obvious from the diff.

## Pull requests

- Squash on merge.
- Include a short test plan in the description.
- Link the related ticket / issue if there is one.
- Don't introduce new third-party dependencies without flagging it.

## Security findings

Don't open public issues for security problems. See [SECURITY.md](SECURITY.md).
