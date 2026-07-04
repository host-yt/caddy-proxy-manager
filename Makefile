# =========================================================================
# Hostyt Proxy Gateway - developer Makefile
# =========================================================================

SHELL := bash
GO    ?= go
PKG   := ./...
BIN   := bin/server

# Tool versions - pin to keep CI and dev in sync.
TEMPL_VERSION    := v0.2.793
GOOSE_VERSION    := v3.22.1
GOLANGCI_VERSION := v1.61.0
TAILWIND_VERSION := v3.4.17

# Standalone Tailwind binary (no Node). Resolved per-OS/arch on demand.
TAILWIND_BIN := bin/tailwindcss

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS=":.*##"; printf "Targets:\n"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# --- Tooling ----------------------------------------------------------------

.PHONY: tools
tools: ## Install dev tools (templ, goose, golangci-lint, air).
	$(GO) install github.com/a-h/templ/cmd/templ@$(TEMPL_VERSION)
	$(GO) install github.com/pressly/goose/v3/cmd/goose@$(GOOSE_VERSION)
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_VERSION)
	$(GO) install github.com/air-verse/air@latest

# --- Codegen ----------------------------------------------------------------

.PHONY: gen
gen: gen-templ ## Run all codegen.

.PHONY: gen-templ
gen-templ: ## Generate templ Go from .templ files.
	templ generate

# --- DB migrations ----------------------------------------------------------

GOOSE_DRIVER := mysql
GOOSE_DBSTRING ?= $(DB_USER):$(DB_PASSWORD)@tcp($(DB_HOST):$(DB_PORT))/$(DB_NAME)?parseTime=true

.PHONY: migrate-up
migrate-up: ## Apply migrations.
	goose -dir migrations $(GOOSE_DRIVER) "$(GOOSE_DBSTRING)" up

.PHONY: migrate-down
migrate-down: ## Roll back last migration.
	goose -dir migrations $(GOOSE_DRIVER) "$(GOOSE_DBSTRING)" down

.PHONY: migrate-status
migrate-status: ## Show migration status.
	goose -dir migrations $(GOOSE_DRIVER) "$(GOOSE_DBSTRING)" status

.PHONY: migrate-new
migrate-new: ## Create migration: make migrate-new name=add_xyz
	goose -dir migrations create $(name) sql

# --- CSS (Tailwind) ---------------------------------------------------------

# Download the standalone tailwind binary for this host once (cached in bin/).
$(TAILWIND_BIN):
	@mkdir -p bin
	@os=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	 arch=$$(uname -m); \
	 case "$$arch" in x86_64|amd64) arch=x64 ;; arm64|aarch64) arch=arm64 ;; esac; \
	 url="https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-$$os-$$arch"; \
	 echo "downloading $$url"; \
	 curl -sSL -o $(TAILWIND_BIN) "$$url" && chmod +x $(TAILWIND_BIN)

.PHONY: build-css
build-css: $(TAILWIND_BIN) ## Build web/static/css/tailwind.css (needed for dev + embed).
	$(TAILWIND_BIN) -c tailwind.config.js \
	  -i web/static/css/tailwind.input.css \
	  -o web/static/css/tailwind.css --minify

# --- Build / run ------------------------------------------------------------

.PHONY: build
build: gen build-css ## Build server binary (CSS first so it embeds).
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/server

.PHONY: run
run: build-css ## Run locally (loads .env).
	$(GO) run ./cmd/server

.PHONY: dev
dev: build-css ## Hot-reload dev (air + templ watcher).
	air

# --- Quality ----------------------------------------------------------------

.PHONY: fmt
fmt: ## gofmt + goimports.
	$(GO) fmt $(PKG)

.PHONY: vet
vet:
	$(GO) vet $(PKG)

.PHONY: lint
lint: ## golangci-lint.
	golangci-lint run

.PHONY: test
test: ## Run tests with race detector.
	$(GO) test -race -count=1 $(PKG)

.PHONY: cover
cover: ## Test coverage report.
	$(GO) test -race -coverprofile=coverage.txt -covermode=atomic $(PKG)
	$(GO) tool cover -func=coverage.txt | tail -1

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: check-migrations
check-migrations: ## Verify no .sql file lives in a migrations/ subdirectory (goose ignores them).
	@bad=$$(find migrations -mindepth 2 -name '*.sql'); \
	 if [ -n "$$bad" ]; then \
	   echo "ERROR: .sql files in subdirectories won't be run by goose:"; \
	   echo "$$bad"; \
	   exit 1; \
	 fi
	@echo "check-migrations: OK (all .sql files are flat in migrations/)"

.PHONY: check
check: fmt vet lint test check-migrations ## Full pre-commit check.

# --- Docker -----------------------------------------------------------------

.PHONY: docker-build
docker-build:
	docker compose -f deploy/docker-compose.yml build

.PHONY: docker-up
docker-up:
	docker compose -f deploy/docker-compose.yml up -d

.PHONY: docker-down
docker-down:
	docker compose -f deploy/docker-compose.yml down

.PHONY: docker-logs
docker-logs:
	docker compose -f deploy/docker-compose.yml logs -f --tail=200

# --- Edge Caddy image (WAF / cache / L4 / geoip / rate-limit) ---------------
# Standalone build+push of the custom Caddy image so it can be rolled to EVERY
# node (central + remote joins) BEFORE flipping WAF_MODULE_AVAILABLE=1. Stock
# Caddy rejects the WAF/cache config on /load and the node goes offline, so all
# nodes must run this image first. See docs/WAF.md enablement runbook.
EDGE_IMAGE ?= ghcr.io/host-yt/caddy-proxy-manager-edge:latest

.PHONY: edge-image
edge-image:
	docker build -t $(EDGE_IMAGE) deploy/caddy

.PHONY: edge-push
edge-push: edge-image
	docker push $(EDGE_IMAGE)

# --- Clean ------------------------------------------------------------------

.PHONY: clean
clean:
	rm -rf bin tmp dist coverage.txt
