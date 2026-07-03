# syntax=docker/dockerfile:1.7
# =========================================================================
# Caddy node image. Custom build via xcaddy embeds the Souin cache module
# so the panel's per-route `cache_enabled` flag turns into a real origin
# cache (stock caddy:2.11.4 only ships Cache-Control header emission). Same
# image is used by both the central panel node and remote join nodes.
#
# Pinned versions: bump on Caddy minor releases (sync `FROM caddy:X.Y`
# below) and audit the cache-handler tag against its CHANGELOG before
# moving past v2.x.x.
# =========================================================================
FROM caddy:2.11.4-builder AS builder
# Souin cache-handler (per-route real cache) + caddy-l4 (TCP/UDP stream
# proxy used by the Streams admin page) + caddy-ratelimit (per-route
# rate_limit handler, gated by RATE_LIMIT_AVAILABLE) + coraza WAF (per-route
# OWASP CRS, gated by WAF_MODULE_AVAILABLE) + maxmind-geolocation (per-route
# country allow/deny matcher, gated by GEOIP_AVAILABLE; needs the mmdb at
# /data/geoip auto-distributed by the panel). cache-handler uses v0.x.x - no
# v2.x exists.
# Every module is pinned (@tag or @commit) for reproducible builds. The three
# caddy-dns modules with no release (digitalocean/vultr/dnsimple) pin a commit.
# DNS-01 wildcard providers. This caddy-dns/<module> list is kept in sync by
# hand with the Go provider registry (internal/caddyapi/dnsproviders.go): a
# selected provider whose module is NOT built makes Caddy reject the whole
# /load, so the two MUST match exactly (DNSProviderModules()).
RUN xcaddy build \
      --with github.com/caddyserver/cache-handler@v0.16.0 \
      --with github.com/mholt/caddy-l4@v0.1.1 \
      --with github.com/mholt/caddy-ratelimit@v0.1.0 \
      --with github.com/corazawaf/coraza-caddy/v2@v2.5.0 \
      --with github.com/porech/caddy-maxmind-geolocation@v1.0.3 \
      --with github.com/caddy-dns/cloudflare@v0.2.4 \
      --with github.com/caddy-dns/route53@v1.6.2 \
      --with github.com/caddy-dns/googleclouddns@v1.1.0 \
      --with github.com/caddy-dns/azure@v0.6.0 \
      --with github.com/caddy-dns/digitalocean@04bde2867106aa1b44c2f9da41a285fa02e629c5 \
      --with github.com/caddy-dns/hetzner@v2.0.1 \
      --with github.com/caddy-dns/linode@v0.8.0 \
      --with github.com/caddy-dns/vultr@55bf3e9768beb9c465cc795fba6ee774573a5d22 \
      --with github.com/caddy-dns/ovh@v1.1.0 \
      --with github.com/caddy-dns/gandi@v1.1.0 \
      --with github.com/caddy-dns/namecheap@v1.0.0 \
      --with github.com/caddy-dns/godaddy@v1.2.0 \
      --with github.com/caddy-dns/dnsimple@0433343c56102ab9415e95486fb3dbba4a2e7d55 \
      --with github.com/caddy-dns/porkbun@v0.3.1 \
      --with github.com/caddy-dns/desec@v1.1.0 \
      --with github.com/caddy-dns/alidns@v1.0.29 \
      --with github.com/caddy-dns/netcup@v1.0.0 \
      --with github.com/caddy-dns/powerdns@v1.0.2

FROM caddy:2.11.4
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Bake the Caddyfile into the image so deploys (Portainer, plain compose,
# k8s) don't need to bind-mount it from the host. Operators that want to
# override per-deployment can still mount /etc/caddy/Caddyfile; without
# a mount, this baked copy is used.
COPY Caddyfile /etc/caddy/Caddyfile

EXPOSE 80 443 443/udp 2019
