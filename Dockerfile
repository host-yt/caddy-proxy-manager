# syntax=docker/dockerfile:1.7
# =========================================================================
# Hostyt Proxy Gateway - app image (multi-stage, distroless final)
# =========================================================================
# Base images are pinned by digest (@sha256:...), not just tag, so the exact
# bytes CI scans are the ones that ship. Dependabot (.github/dependabot.yml)
# opens PRs to roll the digest forward; a manual bump can be verified with
# `docker buildx imagetools inspect <image>:<tag> --format '{{json .Manifest}}'`.

# ---- Stage 0: tailwind build -------------------------------------------
# Standalone tailwindcss binary scans every template and emits one
# minified stylesheet shipped under /static/css/tailwind.css. Lets us
# drop the CDN runtime script (Tailwind's own console nag + extra RTT)
# without dragging Node into the build.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS tailwind
ARG TW_VERSION=v3.4.17
ARG TARGETARCH
# Pinned sha256 of the v3.4.17 release binaries - verified via `shasum -a 256`
# against the GitHub release download. Update both when bumping TW_VERSION.
ARG TW_SHA256_AMD64=7d24f7fa191d2193b78cd5f5a42a6093e14409521908529f42d80b11fde1f1d4
ARG TW_SHA256_ARM64=69b1378b8133192d7d2feb12a116fa12d035594f58db3eff215879e4ad8cf39b
# Map docker TARGETARCH to tailwind's release naming (amd64->x64, arm64->arm64).
RUN apk add --no-cache curl ca-certificates \
 && case "${TARGETARCH}" in \
      amd64) TW_ARCH=x64; TW_SHA256="${TW_SHA256_AMD64}" ;; \
      arm64) TW_ARCH=arm64; TW_SHA256="${TW_SHA256_ARM64}" ;; \
      *) echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -sSL -o /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/${TW_VERSION}/tailwindcss-linux-${TW_ARCH}" \
 && echo "${TW_SHA256}  /usr/local/bin/tailwindcss" | sha256sum -c - \
 && chmod +x /usr/local/bin/tailwindcss
WORKDIR /src
COPY tailwind.config.js ./
COPY web/static/css/tailwind.input.css ./web/static/css/tailwind.input.css
# themes.css is @import'd by tailwind.input.css (relative path) at build time.
COPY web/static/css/themes.css ./web/static/css/themes.css
COPY internal/view ./internal/view
RUN tailwindcss \
      -c tailwind.config.js \
      -i web/static/css/tailwind.input.css \
      -o /out/tailwind.css \
      --minify

# ---- Stage 1: codegen + build ------------------------------------------
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src

RUN apk add --no-cache git ca-certificates tzdata

# Cache deps first.
COPY go.mod go.sum* ./
RUN go mod download

# Install codegen tools used at build time.
RUN go install github.com/a-h/templ/cmd/templ@v0.2.793

COPY . .

# Bring the built CSS into the source tree BEFORE `go build` so the
# //go:embed all:web/static in embed.go captures it (self-contained binary).
COPY --from=tailwind /out/tailwind.css ./web/static/css/tailwind.css

# Generate templ. Fail the build on real codegen errors instead of shipping
# stale generated files; skip cleanly when no source is present. (sqlc removed:
# the app uses raw database/sql; its MySQL parser never handled our migrations.)
RUN if find internal -name '*.templ' | grep -q .; then templ generate; fi

# Static build. TARGETARCH comes from buildx so cross-arch builds (arm64
# from an amd64 runner) emit the right ELF instead of host-native.
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/server ./cmd/server

# Operator restore tool (issue #6): decrypts .tgz.age backup artifacts.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" \
      -o /out/hpg-restore ./cmd/restore

# Prepare runtime dirs with correct ownership (distroless has no RUN).
# Docker stamps a fresh named volume with the ownership of the image
# directory it is mounted over, but ONLY when that directory has content -
# an empty one is skipped and the mountpoint stays root:root, which the
# nonroot app (65532) cannot write. Hence the .keep markers: without them
# wg_config lands root-owned and mesh WireGuard is dead on a fresh install
# ("write tmp: /app/wg/wg0.conf.tmp: permission denied"), and app_data the
# same for a SQLite install.
RUN mkdir -p /out/data /out/wg \
 && touch /out/data/.keep /out/wg/.keep \
 && chown -R 65532:65532 /out/data /out/wg

# ---- Stage 2: runtime --------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
WORKDIR /app

COPY --from=build /out/server /app/server
# Operator restore tool (issue #6): decrypts .tgz.age backup artifacts.
COPY --from=build /out/hpg-restore /app/hpg-restore
COPY --from=build /src/web /app/web
COPY --from=tailwind /out/tailwind.css /app/web/static/css/tailwind.css
COPY --from=build /src/migrations /app/migrations
COPY --from=build --chown=65532:65532 /out/data /app/data
COPY --from=build --chown=65532:65532 /out/wg /app/wg

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/server"]
