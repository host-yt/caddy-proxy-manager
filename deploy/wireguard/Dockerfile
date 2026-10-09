# Minimal WireGuard sidecar.
# Brings up wg0 from /config/wg0.conf, then watches the file and applies
# changes via `wg syncconf` (zero-downtime peer add/remove).
FROM alpine:3.24

RUN apk add --no-cache wireguard-tools iptables bash coreutils

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Sidecar runs in the host network namespace (set in compose).
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint -- wg-quick needs root
ENTRYPOINT ["/entrypoint.sh"]
