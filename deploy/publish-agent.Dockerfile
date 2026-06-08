# syntax=docker/dockerfile:1
#
# Multi-arch contributor agent image for Docker Hub (s4l3h1/meshcheck:agent).
# Like deploy/agent.Dockerfile it is FROM scratch and compiles nothing — it
# packages the pre-built, version-/key-stamped static binary from dist/. Build
# dist/ first (see the Makefile):
#
#   make build      # cross-compiles the agent for amd64 AND arm64 into dist/
#
# Unlike deploy/agent.Dockerfile (single-arch, used by the local fleet and the
# SSH-deployed amd64 agent), this image is driven by `docker buildx build
# --platform linux/amd64,linux/arm64`: buildx sets TARGETARCH per platform and
# assembles the two builds into one manifest list pushed under a single tag, so
# `docker pull s4l3h1/meshcheck:agent` auto-selects the host's architecture.
# There is no RUN here, so no QEMU emulation is involved. See the `publish`
# target and doc/guides/node-install.md.

FROM scratch

ARG TARGETARCH

COPY dist/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY dist/agent-${TARGETARCH}/meshcheck-agent /bin/meshcheck-agent

ENTRYPOINT ["/bin/meshcheck-agent"]
