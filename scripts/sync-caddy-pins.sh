#!/usr/bin/env bash
# sync-caddy-pins.sh - make every stock Caddy pin match deploy/caddy/Dockerfile.
#
# Dependabot rolls the edge image's runtime stage forward
# (FROM caddy:X.Y.Z@sha256:...), but the same stock image is pinned in the
# compose files, the remote-node stack, node-join.sh and the docs. CI's
# "one Caddy version across every pin" gate then fails the PR. This script
# reads the version and digest from the Dockerfile's runtime stage (the
# single source of truth) and rewrites every other pin to it:
#
#   caddy:A.B.C@sha256:<old>  ->  caddy:X.Y.Z@sha256:<new>
#   caddy:A.B.C (bare text)   ->  caddy:X.Y.Z
#
# The builder stage (caddy:X.Y.Z-builder@...) is left to Dependabot: it has
# its own digest. Run from the repository root. Idempotent; prints what it
# changed and exits 0 either way. Used by .github/workflows/caddy-pin-sync.yml
# and by `make caddy-pins`.
set -euo pipefail

dockerfile=deploy/caddy/Dockerfile
# Same file set as CI's pin gate (.github/workflows/ci.yml).
files=(
  deploy/caddy/Dockerfile
  deploy/docker-compose.lite.yml
  deploy/integration/docker-compose.sqlite.yml
  deploy/integration/docker-compose.multinode.yml
  deploy/remote-node/docker-compose.yml
  scripts/node-join.sh
  README.md
)
while IFS= read -r f; do files+=("$f"); done < <(grep -rlE 'caddy:2\.[0-9]+\.[0-9]+' docs/ || true)

runtime=$(grep -E '^FROM caddy:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}' "$dockerfile" | tail -n1 || true)
[[ -n "$runtime" ]] || { echo "no 'FROM caddy:X.Y.Z@sha256:...' runtime stage in $dockerfile" >&2; exit 1; }
ver=$(sed -E 's/^FROM caddy:([0-9]+\.[0-9]+\.[0-9]+)@.*/\1/' <<<"$runtime")
digest=$(sed -E 's/^FROM caddy:[^@]+@(sha256:[0-9a-f]{64}).*/\1/' <<<"$runtime")

existing=()
for f in "${files[@]}"; do [[ -f "$f" ]] && existing+=("$f"); done
before=$(cat "${existing[@]}" | sha256sum)

for f in "${existing[@]}"; do
  # Digest-pinned stock image (not the -builder variant), then bare mentions.
  # The bare rule skips "-builder" so the builder stage keeps its own pin.
  VER="$ver" DIGEST="$digest" perl -pi -e '
    s{caddy:\d+\.\d+\.\d+\@sha256:[0-9a-f]{64}}{caddy:$ENV{VER}\@$ENV{DIGEST}}g;
    s{caddy:\d+\.\d+\.\d+(?!\d|\.\d|-builder|\@)}{caddy:$ENV{VER}}g;
  ' "$f"
done

if [[ "$(cat "${existing[@]}" | sha256sum)" == "$before" ]]; then
  echo "caddy pins already at $ver"
else
  echo "caddy pins synced to $ver ($digest)"
fi
