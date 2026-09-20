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
ARG WSTUNNEL_VERSION=11.0.0
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) WST_ASSET="wstunnel_${WSTUNNEL_VERSION}_linux_amd64.tar.gz"; WST_SHA="9708a99717b5a951453c2ff7c14c25d3418d02ca7fcb96fdb382a8f2083bab5e" ;; \
      arm64) WST_ASSET="wstunnel_${WSTUNNEL_VERSION}_linux_arm64.tar.gz"; WST_SHA="b86abf73e340ed0c3ff9a77a5458aa27213784920ec65513132b36def45edc94" ;; \
      arm)   WST_ASSET="wstunnel_${WSTUNNEL_VERSION}_linux_armv7.tar.gz"; WST_SHA="50e2855b527869b77402a902b58b83872ddd24271550df289b54729836c8abbc" ;; \
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
