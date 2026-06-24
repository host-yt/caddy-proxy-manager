# syntax=docker/dockerfile:1.7
# =========================================================================
# Caddy node image. Custom build via xcaddy embeds the Souin cache module
# so the panel's per-route `cache_enabled` flag turns into a real origin
# cache (stock caddy:2.11.3 only ships Cache-Control header emission). Same
# image is used by both the central panel node and remote join nodes.
#
# Pinned versions: bump on Caddy minor releases (sync `FROM caddy:X.Y`
# below) and audit the cache-handler tag against its CHANGELOG before
# moving past v2.x.x.
# =========================================================================
FROM caddy:2.11.3-builder AS builder
# Souin cache-handler (per-route real cache) + caddy-l4 (TCP/UDP stream
# proxy used by the Streams admin page) + caddy-ratelimit (per-route
# rate_limit handler, gated by RATE_LIMIT_AVAILABLE) + coraza WAF (per-route
# OWASP CRS, gated by WAF_MODULE_AVAILABLE). cache-handler uses v0.x.x - no
# v2.x exists. caddy-l4/caddy-ratelimit have no stable tag, latest commit on
# master is what xcaddy resolves with no @ pin.
# DNS-01 wildcard providers. This caddy-dns/<module> list is kept in sync by
# hand with the Go provider registry (internal/caddyapi/dnsproviders.go): a
# selected provider whose module is NOT built makes Caddy reject the whole
# /load, so the two MUST match exactly (DNSProviderModules()).
RUN xcaddy build \
      --with github.com/caddyserver/cache-handler@v0.16.0 \
      --with github.com/mholt/caddy-l4 \
      --with github.com/mholt/caddy-ratelimit \
      --with github.com/corazawaf/coraza-caddy/v2 \
      --with github.com/caddy-dns/cloudflare \
      --with github.com/caddy-dns/route53 \
      --with github.com/caddy-dns/googleclouddns \
      --with github.com/caddy-dns/azure \
      --with github.com/caddy-dns/digitalocean \
      --with github.com/caddy-dns/hetzner \
      --with github.com/caddy-dns/linode \
      --with github.com/caddy-dns/vultr \
      --with github.com/caddy-dns/ovh \
      --with github.com/caddy-dns/gandi \
      --with github.com/caddy-dns/namecheap \
      --with github.com/caddy-dns/godaddy \
      --with github.com/caddy-dns/dnsimple \
      --with github.com/caddy-dns/porkbun \
      --with github.com/caddy-dns/desec \
      --with github.com/caddy-dns/alidns \
      --with github.com/caddy-dns/netcup \
      --with github.com/caddy-dns/powerdns

FROM caddy:2.11.3
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Bake the Caddyfile into the image so deploys (Portainer, plain compose,
# k8s) don't need to bind-mount it from the host. Operators that want to
# override per-deployment can still mount /etc/caddy/Caddyfile; without
# a mount, this baked copy is used.
COPY Caddyfile /etc/caddy/Caddyfile

EXPOSE 80 443 443/udp 2019
