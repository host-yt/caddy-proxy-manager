# Minimal WireGuard sidecar.
# Brings up wg0 from /config/wg0.conf, then watches the file and applies
# changes via `wg syncconf` (zero-downtime peer add/remove).
FROM alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a

RUN apk upgrade --no-cache && apk add --no-cache wireguard-tools iptables bash coreutils

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Sidecar runs in the host network namespace (set in compose).
# nosemgrep: dockerfile.security.missing-user-entrypoint.missing-user-entrypoint -- wg-quick needs root
ENTRYPOINT ["/entrypoint.sh"]
