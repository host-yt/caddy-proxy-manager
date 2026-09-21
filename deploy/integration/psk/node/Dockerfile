# Test "node" host for the mesh-PSK e2e harness.
#
# Stands in for a bare Debian box that an operator runs node-join.sh on:
# real bash, curl, jq, wireguard-tools and a real kernel wg0. The only
# stand-in is `docker` (see docker-shim) - node-join.sh's last step starts
# Caddy in a container, which would mean docker-in-docker for no extra
# coverage of the WireGuard paths this harness exists to test.
FROM caddy:2.11.4 AS caddybin

FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      wireguard-tools iproute2 iptables curl jq ca-certificates procps \
      openresolv iputils-ping \
  && rm -rf /var/lib/apt/lists/*
COPY --from=caddybin /usr/bin/caddy /usr/bin/caddy
COPY docker-shim /usr/local/bin/docker
RUN chmod +x /usr/local/bin/docker
CMD ["sleep", "infinity"]
