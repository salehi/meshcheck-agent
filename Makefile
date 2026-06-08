# MeshCheck Node agent — build & publish.
#
# The agent is a single static Go binary. Build and publish run entirely in
# containers — there is no host Go toolchain. Compilation is OFFLINE from the
# committed vendor/ tree; only `publish` (the registry push) needs the network.
#
# Typical loop after changing Go code:        make build
# After adding/upgrading a dependency:        make tidy && make vendor && make build
# After changing proto/agent.proto:           make proto && make build

# Use docker-compose (v2 standalone), not the `docker compose` plugin.
COMPOSE     ?= docker-compose
GO_IMAGE    ?= golang:1.23
# named volume holding the Go module cache
MOD_CACHE   ?= meshcheck_agent_gomod
# AGENT_REPO is the Docker Hub repo for the published agent image; PLATFORMS are
# the architectures it is published for.
AGENT_REPO  ?= s4l3h1/meshcheck
PLATFORMS   ?= linux/amd64,linux/arm64,linux/arm/v7
UID         := $(shell id -u)
GID         := $(shell id -g)

export DOCKER_BUILDKIT = 1

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@echo "MeshCheck agent — make targets:"
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# --- modules -------------------------------------------------------------

.PHONY: tidy
tidy: ## Recompute go.mod/go.sum from the source (run after changing imports/deps)
	@echo "==> go mod tidy (in $(GO_IMAGE))"
	docker run --rm -v "$(CURDIR)":/src -v $(MOD_CACHE):/go/pkg/mod -w /src \
	  -e GOSUMDB=off $(GO_IMAGE) go mod tidy
	docker run --rm -v "$(CURDIR)":/src -w /src $(GO_IMAGE) chown -R $(UID):$(GID) go.mod go.sum

.PHONY: vendor
vendor: ## Refresh vendor/ from go.mod (run after adding/upgrading a dependency)
	@echo "==> go mod vendor (in $(GO_IMAGE))"
	docker run --rm -v "$(CURDIR)":/src -v $(MOD_CACHE):/go/pkg/mod -w /src \
	  -e GOSUMDB=off $(GO_IMAGE) go mod vendor
	@echo "==> fixing vendor/ ownership"
	docker run --rm -v "$(CURDIR)":/src -w /src $(GO_IMAGE) chown -R $(UID):$(GID) vendor

# --- build pipeline ------------------------------------------------------

# The agent binary is stamped at build time with the release version (from the
# VERSION file) and the base64 Ed25519 release-signing public key (the committed
# public half; the private half is offline). An absent key yields a dev build
# that refuses to self-update.
AGENT_VERSION      ?= $(shell cat VERSION 2>/dev/null)
RELEASE_PUBKEY_B64 ?= $(shell cat deploy/release-pubkey.b64 2>/dev/null)

.PHONY: build
build: ## Cross-compile the agent (amd64+arm64+armv7) into dist/ (offline, from vendor/)
	@echo "==> building agent into dist/ (offline, v$(AGENT_VERSION))"
	docker build -f deploy/build.Dockerfile \
	  --build-arg AGENT_VERSION="$(AGENT_VERSION)" \
	  --build-arg RELEASE_PUBKEY_B64="$(RELEASE_PUBKEY_B64)" \
	  --target dist --output dist .
	@echo "==> dist/ now holds:" && ls -lh dist/

.PHONY: agent-tars
agent-tars: ## Package loadable agent Docker image tars (amd64+arm64+arm) into dist/downloads/
	@test -f dist/agent-arm64/meshcheck-agent || { echo "agent binaries missing — run 'make build' first"; exit 1; }
	@echo "==> building + saving agent image tars (docker load) into dist/downloads/"
	@for arch in amd64 arm64 arm; do \
	  case "$$arch" in \
	    amd64) bin=dist/meshcheck-agent; plat=linux/amd64 ;; \
	    arm64) bin=dist/agent-arm64/meshcheck-agent; plat=linux/arm64 ;; \
	    arm)   bin=dist/agent-arm/meshcheck-agent; plat=linux/arm/v7 ;; \
	  esac; \
	  printf 'FROM scratch\nCOPY %s /bin/meshcheck-agent\nCOPY dist/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\nENTRYPOINT ["/bin/meshcheck-agent"]\n' "$$bin" \
	    | docker build --platform $$plat -t meshcheck/agent:latest -f - . ; \
	  docker save meshcheck/agent:latest -o dist/downloads/meshcheck-agent_linux_$$arch.docker.tar ; \
	  chmod 0644 dist/downloads/meshcheck-agent_linux_$$arch.docker.tar ; \
	done
	@echo "==> dist/downloads/ now holds:" && ls -lh dist/downloads/

# --- publish -------------------------------------------------------------
# `publish` builds a single multi-arch manifest list — `docker pull
# $(AGENT_REPO):agent` then auto-selects the host's architecture. Compilation
# stays offline (committed vendor/, `make build`); only this push step is online.
# Requires the host to be logged in to Docker Hub already.

.PHONY: buildx-init
buildx-init: ## Create the multi-arch buildx builder (idempotent)
	docker buildx create --name meshcheck --driver docker-container --use 2>/dev/null \
	  || docker buildx use meshcheck

.PHONY: publish
publish: build buildx-init ## Build+push the multi-arch agent image to Docker Hub
	@echo "==> publishing $(AGENT_REPO):agent ($(PLATFORMS)) v$(AGENT_VERSION)"
	docker buildx build --platform $(PLATFORMS) \
	  -f deploy/publish-agent.Dockerfile \
	  -t $(AGENT_REPO):agent \
	  -t $(AGENT_REPO):agent-$(AGENT_VERSION) \
	  --push .

# --- codegen / test ------------------------------------------------------

.PHONY: proto
proto: ## Regenerate pkg/agentpb/agent.pb.go from proto/agent.proto
	$(COMPOSE) -f proto/compose.yaml run --rm codegen
	docker run --rm -v "$(CURDIR)":/src -w /src $(GO_IMAGE) chown -R $(UID):$(GID) pkg/agentpb

.PHONY: test
test: ## Run the Go unit tests in a container (offline, from vendor/)
	@echo "==> go test ./... (in $(GO_IMAGE))"
	docker run --rm -v "$(CURDIR)":/src -v $(MOD_CACHE):/go/pkg/mod -w /src \
	  -e GOFLAGS='-mod=vendor -buildvcs=false' -e GOSUMDB=off \
	  $(GO_IMAGE) go test ./...

.PHONY: clean
clean: ## Remove build artifacts (dist/)
	rm -rf dist/
