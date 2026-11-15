# Test "node" host for the mesh-PSK e2e harness.
#
# Stands in for a bare Debian box that an operator runs node-join.sh on:
# real bash, curl, jq, wireguard-tools and a real kernel wg0. The only
# stand-in is `docker` (see docker-shim) - node-join.sh's last step starts
# Caddy in a container, which would mean docker-in-docker for no extra
# coverage of the WireGuard paths this harness exists to test.
FROM caddy:2.11.8@sha256:4fcafa98afd1c2e642e353e3c5cf9ddbe892fcee14bc990e7ba2c5b78e51f9cf AS caddybin

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      wireguard-tools iproute2 iptables curl jq ca-certificates procps \
      openresolv iputils-ping \
  && rm -rf /var/lib/apt/lists/*
COPY --from=caddybin /usr/bin/caddy /usr/bin/caddy
COPY docker-shim /usr/local/bin/docker
RUN chmod +x /usr/local/bin/docker
# nosemgrep: dockerfile.security.missing-user.missing-user -- integration test container
CMD ["sleep", "infinity"]
