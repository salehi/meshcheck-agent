// SPDX-License-Identifier: Apache-2.0

// Package resultsig implements the canonical Result hashing and Ed25519
// signing scheme shared by the Node agent (which signs) and the platform
// (which verifies).
//
// The canonical form is defined in doc/protocols/agent-protocol.md §Canonical
// Result Hash. Both sides MUST agree on it byte-for-byte, which is the whole
// reason it lives in one package imported by both.
package resultsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"

	"github.com/salehi/meshcheck-agent/pkg/agentpb"
)

// canonicalBytes serialises the signed fields (1–6 of ResultSubmit) into the
// canonical byte sequence:
//
//	task_id || check_id || outcome(uint32 BE) || measurements ||
//	started_at(int64 BE) || completed_at(int64 BE)
func canonicalBytes(taskID, checkID string, outcome agentpb.ResultOutcome, measurements []byte, startedAt, completedAt int64) []byte {
	var b bytes.Buffer
	b.WriteString(taskID)
	b.WriteString(checkID)
	_ = binary.Write(&b, binary.BigEndian, uint32(outcome))
	b.Write(measurements)
	_ = binary.Write(&b, binary.BigEndian, startedAt)
	_ = binary.Write(&b, binary.BigEndian, completedAt)
	return b.Bytes()
}

// Hash returns the SHA-256 of the canonical form of a ResultSubmit. This is
// the digest that is signed, and the value stored in
// results.signature_canonical_hash for audit.
func Hash(r *agentpb.ResultSubmit) []byte {
	sum := sha256.Sum256(canonicalBytes(
		r.GetTaskId(), r.GetCheckId(), r.GetOutcome(),
		r.GetMeasurements(), r.GetStartedAt(), r.GetCompletedAt(),
	))
	return sum[:]
}

// Sign produces the Ed25519 signature placed in ResultSubmit.signature. It
// signs the canonical hash, not the raw bytes, so the same digest can be
// re-verified from stored fields months later.
func Sign(priv ed25519.PrivateKey, r *agentpb.ResultSubmit) []byte {
	return ed25519.Sign(priv, Hash(r))
}

// Verify reports whether r.signature is a valid signature by pub over r's
// canonical hash. A malformed public key yields false rather than a panic.
func Verify(pub ed25519.PublicKey, r *agentpb.ResultSubmit) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, Hash(r), r.GetSignature())
}
