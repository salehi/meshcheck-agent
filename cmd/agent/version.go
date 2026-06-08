// SPDX-License-Identifier: AGPL-3.0-only

package main

// Build-time identity, injected with `-ldflags -X`. The defaults below are what
// a plain `go build` (a developer build) carries; release builds overwrite them
// from the repo's VERSION file and deploy/release-pubkey.b64 (see the Makefile
// and deploy/build.Dockerfile).
//
//	agentVersion  — the semver this binary reports (ClientHello, X-Agent-Version,
//	                and `agent --version`). The platform compares it against the
//	                operator's target to decide whether to offer an update.
//	releasePubB64 — base64 of the Ed25519 release-signing public key. The agent
//	                verifies every update manifest against it; an empty value
//	                (a dev build) disables self-update entirely, so an unsigned
//	                build can never be talked into replacing itself.
var (
	agentVersion  = "0.0.0-dev"
	releasePubB64 = ""
)
