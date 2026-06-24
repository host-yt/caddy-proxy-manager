# syntax=docker/dockerfile:1.7
# =========================================================================
# hpg-node-agent - sidecar that keeps wg-tun0 (customer-tunnel WireGuard
# interface) in sync with the panel's peer list. Run alongside Caddy on
# each tunnel-enabled node.
#
# Run requirements at runtime:
#   --cap-add=NET_ADMIN
#   --device=/dev/net/tun
#   --network=host  (or share the Caddy container's net namespace)
#   env: HPG_PANEL_URL, HPG_NODE_TOKEN, HPG_WG_PRIVATE_KEY, HPG_WG_GATEWAY_IP
# =========================================================================
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# TARGETOS/TARGETARCH from buildx so cross-arch builds emit the right ELF.
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/hpg-node-agent ./cmd/node-agent

FROM alpine:3.20
RUN apk add --no-cache wireguard-tools nftables iproute2 curl ca-certificates tar
# wstunnel for the WSS-over-TLS tunnel transport (HPG_TUNNEL_TRANSPORT=wss|auto).
# Version + per-arch sha256 PINNED (release checksums.txt). Bump together.
ARG TARGETARCH
ARG WSTUNNEL_VERSION=10.5.5
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) WST_ASSET="wstunnel_${WSTUNNEL_VERSION}_linux_amd64.tar.gz"; WST_SHA="b20ffa02e945ec0c0d6b153ba69a290593f0957ed2892aee8f987f715ccd95d6" ;; \
      arm64) WST_ASSET="wstunnel_${WSTUNNEL_VERSION}_linux_arm64.tar.gz"; WST_SHA="db85183da9732f26c110a08e3fffdfcfc4a44d544035d01eeefa708ed23874bb" ;; \
      arm)   WST_ASSET="wstunnel_${WSTUNNEL_VERSION}_linux_armv7.tar.gz"; WST_SHA="c61c804018bf8184a48aee1d543d144e2176fbc60ebf2eea9c716c07a9f83aba" ;; \
      *) echo "unsupported TARGETARCH $TARGETARCH"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/wst.tgz "https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VERSION}/${WST_ASSET}"; \
    echo "${WST_SHA}  /tmp/wst.tgz" | sha256sum -c -; \
    tar -xzf /tmp/wst.tgz -C /tmp; \
    install -m 755 "$(find /tmp -type f -name wstunnel | head -n1)" /usr/local/bin/wstunnel; \
    rm -rf /tmp/wst.tgz; \
    wstunnel --version
COPY --from=build /out/hpg-node-agent /usr/local/bin/hpg-node-agent
ENTRYPOINT ["/usr/local/bin/hpg-node-agent"]
