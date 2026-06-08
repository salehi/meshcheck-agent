#!/usr/bin/env bash
#
# Cross-platform release build of the MeshCheck Node agent.
#
# Produces one static binary per supported desktop platform under dist/. The
# Go toolchain runs inside a container — this repository carries no host
# toolchain (see deploy/Dockerfile, proto/compose.yaml).
#
# Run from anywhere:
#   ./scripts/build-agent.sh

set -euo pipefail

cd "$(dirname "$0")/.."
OUT=dist
mkdir -p "$OUT"

# Stamp the release version (VERSION file) and the base64 Ed25519 release public
# key (committed public half) into each binary; see cmd/agent/version.go. An
# absent key yields a dev build that refuses to self-update.
AGENT_VERSION="$(cat VERSION 2>/dev/null || echo 0.0.0-dev)"
RELEASE_PUBKEY_B64="$(cat deploy/release-pubkey.b64 2>/dev/null || true)"
LDFLAGS="-s -w -X main.agentVersion=${AGENT_VERSION} -X main.releasePubB64=${RELEASE_PUBKEY_B64}"

# Desktop platforms the Phase 4 peer-node beta agent ships for.
PLATFORMS=(
	linux/amd64
	linux/arm64
	linux/arm
	darwin/amd64
	darwin/arm64
	windows/amd64
)

echo "Building the MeshCheck agent for ${#PLATFORMS[@]} platforms..."
for platform in "${PLATFORMS[@]}"; do
	os="${platform%/*}"
	arch="${platform#*/}"
	ext=""
	[ "$os" = windows ] && ext=".exe"
	# 32-bit ARM is pinned to ARMv7; GOARM is ignored for every other arch.
	goarm=""
	[ "$arch" = arm ] && goarm=7
	binary="meshcheck-agent-${os}-${arch}${ext}"
	echo "  $platform -> $OUT/$binary"
	docker run --rm \
		-v "$PWD":/work -w /work \
		-v meshcheck-build-gomod:/gomod -v meshcheck-build-gocache:/gocache \
		-e GOSUMDB=off -e GOPATH=/gomod -e GOCACHE=/gocache \
		-e CGO_ENABLED=0 -e GOOS="$os" -e GOARCH="$arch" -e GOARM="$goarm" \
		golang:1.23-alpine \
		go build -trimpath -ldflags="$LDFLAGS" -o "/work/$OUT/$binary" ./cmd/agent
done

# Container output may be root-owned depending on the Docker setup; best-effort
# hand it back to the invoking user.
chown -R "$(id -u):$(id -g)" "$OUT" 2>/dev/null || true

echo
echo "Done. Release binaries in $OUT/:"
ls -la "$OUT"
