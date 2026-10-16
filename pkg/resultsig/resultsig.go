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

// slotDomain prefixes a SlotResult's canonical form, so a slot signature can
// never be replayed as a ResultSubmit signature or the other way round.
const slotDomain = "meshcheck-slot-result-v1\x00"

// SlotHash returns the SHA-256 of a SlotResult's canonical form:
//
//	"meshcheck-slot-result-v1\0" || assignment_id || 0x00 || slot(int64 BE) ||
//	outcome(uint32 BE) || measurements || started_at(int64 BE) || completed_at(int64 BE)
//
// The 0x00 after the assignment ID keeps an ID from running into the slot.
func SlotHash(r *agentpb.SlotResult) []byte {
	var b bytes.Buffer
	b.WriteString(slotDomain)
	b.WriteString(r.GetAssignmentId())
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, r.GetSlot())
	_ = binary.Write(&b, binary.BigEndian, uint32(r.GetOutcome()))
	b.Write(r.GetMeasurements())
	_ = binary.Write(&b, binary.BigEndian, r.GetStartedAt())
	_ = binary.Write(&b, binary.BigEndian, r.GetCompletedAt())
	sum := sha256.Sum256(b.Bytes())
	return sum[:]
}

// SignSlot produces the signature placed in SlotResult.signature.
func SignSlot(priv ed25519.PrivateKey, r *agentpb.SlotResult) []byte {
	return ed25519.Sign(priv, SlotHash(r))
}

// VerifySlot reports whether r.signature is a valid signature by pub over r's
// canonical slot hash.
func VerifySlot(pub ed25519.PublicKey, r *agentpb.SlotResult) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, SlotHash(r), r.GetSignature())
}
