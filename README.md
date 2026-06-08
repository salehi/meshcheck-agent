# MeshCheck Node Agent

The MeshCheck Node agent is the peer-contributed probe that powers MeshCheck's
reachability monitoring. It connects to the platform's agent gateway over a
Protobuf-over-WebSocket stream, advertises its capabilities, and executes the
Checks the platform dispatches — `ping` (traceroute), `tcp`, `http`, `dns`,
`tls`, and `smtp`. Every Result is signed with the Node's Ed25519 key so the
platform can verify it came from this Node, unchanged.

This repository is the single source of truth for the agent **and** for the
Node ↔ Platform wire contract: the Protobuf schema in [`proto/`](proto/) and the
shared packages under [`pkg/`](pkg/) (`agentpb`, `checkspec`, `resultsig`,
`version`, `release`). The platform server vendors these same packages, so the
two sides can never drift on the protocol or the result-signing scheme.

## Build

Everything builds in containers — no host Go toolchain is required, and the
compile step is fully offline from the committed `vendor/` tree.

```sh
make build        # cross-compile amd64 + arm64 + armv7 into dist/
make test         # run the unit tests (offline, from vendor/)
make publish      # build + push the multi-arch image to a registry (online)
```

`make build` stamps the binary with the version from [`VERSION`](VERSION) and the
release-signing **public** key from [`deploy/release-pubkey.b64`](deploy/release-pubkey.b64).
A build with no embedded public key (a plain `go build`) is a dev build that
refuses to self-update.

After changing `proto/agent.proto`, regenerate the Go types with `make proto`.
After changing imports/dependencies, run `make tidy && make vendor`.

## Run

The agent needs an **API key** (issued when you register a Node with a MeshCheck
platform) and the platform's **gateway URL**. Provide them via environment
variables or a JSON config file.

Docker:

```sh
docker run -d --restart unless-stopped \
  -e MESHCHECK_AGENT_API_KEY=mck_live_... \
  -e MESHCHECK_AGENT_GATEWAY_URL=wss://your-platform.example/agent \
  -v meshcheck-agent-data:/data \
  <your-image>
```

Binary:

```sh
meshcheck-agent init     # write a starter /etc/meshcheck/agent.json (0600) and exit
meshcheck-agent          # run
meshcheck-agent --version
```

### Configuration

Resolved from a JSON config file first, then the environment (environment wins).
The config file holds the API key and must not be group/world-readable.

| Config key (`agent.json`) | Environment variable | Notes |
|---|---|---|
| `api_key` | `MESHCHECK_AGENT_API_KEY` | required |
| `gateway_url` | `MESHCHECK_AGENT_GATEWAY_URL` | required, e.g. `wss://host/agent` |
| `key_file` | `MESHCHECK_AGENT_KEY_FILE` | Ed25519 signing key path (default `/var/lib/meshcheck/agent.key`) |
| `name` | `MESHCHECK_AGENT_NAME` | human-readable label |
| `city` / `country` | `MESHCHECK_AGENT_CITY` / `_COUNTRY` | self-declared location |
| `connection_class` | `MESHCHECK_AGENT_CONNECTION_CLASS` | `vps` \| `residential_wired` \| `residential_wireless` \| `office` \| `mobile` |
| `log_level` | `MESHCHECK_AGENT_LOG_LEVEL` | `debug` \| `info` \| `warn` \| `error` |
| `max_concurrent_tasks` | `MESHCHECK_AGENT_MAX_CONCURRENT_TASKS` | agent-side task ceiling |
| `auto_update` | `MESHCHECK_AGENT_AUTO_UPDATE` | replace own binary on a signed release (default off) |

The signing key (`key_file`) is generated on first run and **must stay stable**:
the platform records its public half on the first connection and treats it as
immutable. Persist `/data` (or wherever `key_file` lives) across restarts.

`ping` Checks use ICMP. The agent advertises the `ping` capability only when it
can open an ICMP socket (requires `CAP_NET_RAW` / root, or a permissive
`net.ipv4.ping_group_range`).

## License

This project uses a split license:

- The **agent program** (`cmd/`, `internal/`) is licensed under the
  **GNU AGPL-3.0-only** — see [`LICENSE`](LICENSE).
- The **shared wire-contract packages** under [`pkg/`](pkg/) are licensed under
  **Apache-2.0** — see [`pkg/LICENSE`](pkg/LICENSE) — so independent agent
  implementations and the MeshCheck platform server can use the protocol and
  result-signing contract without AGPL obligations.

Per-file `SPDX-License-Identifier` headers record which license applies; the
canonical texts are in [`LICENSES/`](LICENSES/).
