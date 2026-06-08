# syntax=docker/dockerfile:1
#
# Build-only image for the MeshCheck Node agent. It cross-compiles the static
# agent binary from the committed vendor/ tree — no module downloads, so it
# builds fully offline — and exports the binaries plus a CA bundle to a local
# directory via BuildKit's --output. Nothing here runs at deploy time; the
# runtime images are deploy/agent.Dockerfile (local/single-arch) and
# deploy/publish-agent.Dockerfile (multi-arch publish).
#
# Usage (see the Makefile `build` target):
#   docker build -f deploy/build.Dockerfile --target dist --output dist .
# leaves on the host:
#   dist/meshcheck-agent, dist/ca-certificates.crt
#   dist/downloads/meshcheck-agent_linux_{amd64,arm64,arm}.tar.gz  (contributor installs)
#   dist/agent-{amd64,arm64,arm}/meshcheck-agent                   (for the image tars / publish)

# --- compile stage ---
FROM golang:1.23 AS build

# Release identity stamped into the agent (see cmd/agent/version.go). The
# Makefile passes these from the VERSION file and the committed public key. An
# absent key yields a dev build that refuses to self-update.
ARG AGENT_VERSION=0.0.0-dev
ARG RELEASE_PUBKEY_B64=

WORKDIR /src

# vendor/ is committed, so -mod=vendor needs no network. The Go build cache is
# mounted so incremental rebuilds stay fast.
COPY . .

RUN mkdir -p /out && cp /etc/ssl/certs/ca-certificates.crt /out/ca-certificates.crt

# The agent is published for linux/amd64, linux/arm64, and 32-bit linux/arm
# (ARMv7 — mid-range MikroTik / Raspberry-Pi-class boards) so contributors can
# install it on any of them. The amd64 build is also the canonical
# dist/meshcheck-agent used by the runtime agent image and the local fleet.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor \
        -trimpath -tags timetzdata \
        -ldflags="-s -w -X main.agentVersion=${AGENT_VERSION} -X main.releasePubB64=${RELEASE_PUBKEY_B64}" \
        -o /out/meshcheck-agent ./cmd/agent
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod=vendor \
        -trimpath -tags timetzdata \
        -ldflags="-s -w -X main.agentVersion=${AGENT_VERSION} -X main.releasePubB64=${RELEASE_PUBKEY_B64}" \
        -o /out/agent-arm64/meshcheck-agent ./cmd/agent
# 32-bit ARM is pinned to GOARM=7 (ARMv7); ARMv6 and older are not supported.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -mod=vendor \
        -trimpath -tags timetzdata \
        -ldflags="-s -w -X main.agentVersion=${AGENT_VERSION} -X main.releasePubB64=${RELEASE_PUBKEY_B64}" \
        -o /out/agent-arm/meshcheck-agent ./cmd/agent

# Package the downloadable tarballs. Each carries the agent binary and the CA
# bundle it needs for outbound HTTPS checks.
RUN mkdir -p /out/downloads /out/pkg-amd64 /out/pkg-arm64 /out/pkg-arm && \
    cp /out/meshcheck-agent             /out/pkg-amd64/meshcheck-agent && \
    cp /out/agent-arm64/meshcheck-agent /out/pkg-arm64/meshcheck-agent && \
    cp /out/agent-arm/meshcheck-agent   /out/pkg-arm/meshcheck-agent && \
    cp /out/ca-certificates.crt /out/pkg-amd64/ && \
    cp /out/ca-certificates.crt /out/pkg-arm64/ && \
    cp /out/ca-certificates.crt /out/pkg-arm/ && \
    tar -C /out/pkg-amd64 -czf /out/downloads/meshcheck-agent_linux_amd64.tar.gz . && \
    tar -C /out/pkg-arm64 -czf /out/downloads/meshcheck-agent_linux_arm64.tar.gz . && \
    tar -C /out/pkg-arm   -czf /out/downloads/meshcheck-agent_linux_arm.tar.gz . && \
    rm -rf /out/pkg-amd64 /out/pkg-arm64 /out/pkg-arm

# --- export stage ---
# A scratch stage holding only the artifacts, so `docker build --output dist`
# writes just these files to the host dist/ directory.
FROM scratch AS dist
COPY --from=build /out/meshcheck-agent /meshcheck-agent
COPY --from=build /out/ca-certificates.crt /ca-certificates.crt
COPY --from=build /out/downloads/ /downloads/
# Per-arch agent binaries under a uniform dist/agent-<arch>/ layout, so the
# multi-arch publish image (deploy/publish-agent.Dockerfile) can COPY by the
# buildx TARGETARCH. amd64 also stays at /meshcheck-agent (above) for the
# runtime agent image and the local fleet.
COPY --from=build /out/meshcheck-agent /agent-amd64/meshcheck-agent
COPY --from=build /out/agent-arm64/meshcheck-agent /agent-arm64/meshcheck-agent
COPY --from=build /out/agent-arm/meshcheck-agent /agent-arm/meshcheck-agent
