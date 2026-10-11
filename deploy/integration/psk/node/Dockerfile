# Test "node" host for the mesh-PSK e2e harness.
#
# Stands in for a bare Debian box that an operator runs node-join.sh on:
# real bash, curl, jq, wireguard-tools and a real kernel wg0. The only
# stand-in is `docker` (see docker-shim) - node-join.sh's last step starts
# Caddy in a container, which would mean docker-in-docker for no extra
# coverage of the WireGuard paths this harness exists to test.
FROM caddy:2.11.7@sha256:f2a1290d0463aad60660d4ec134943f183ee2a5f6c3eb7bf32dd984f2f020772 AS caddybin

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      wireguard-tools iproute2 iptables curl jq ca-certificates procps \
      openresolv iputils-ping \
  && rm -rf /var/lib/apt/lists/*
COPY --from=caddybin /usr/bin/caddy /usr/bin/caddy
COPY docker-shim /usr/local/bin/docker
RUN chmod +x /usr/local/bin/docker
# nosemgrep: dockerfile.security.missing-user.missing-user -- integration test container
CMD ["sleep", "infinity"]
