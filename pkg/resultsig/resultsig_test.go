package resultsig

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/salehi/meshcheck-agent/pkg/agentpb"
)

func TestSlotSignatureRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	r := &agentpb.SlotResult{
		AssignmentId: "01M52C3D8QHNWGJKSTEVWFXT5H", Slot: 176_000_000,
		Outcome: agentpb.ResultOutcome_RESULT_OUTCOME_PASS, Measurements: []byte(`{"rtt_avg_ms":12}`),
		StartedAt: 1_760_000_003_250, CompletedAt: 1_760_000_003_290,
	}
	r.Signature = SignSlot(priv, r)
	if !VerifySlot(pub, r) {
		t.Fatal("a freshly signed slot result does not verify")
	}
	r.Slot++
	if VerifySlot(pub, r) {
		t.Error("changing the slot keeps the signature valid")
	}
}

func TestSlotAndTaskHashesDiffer(t *testing.T) {
	// The same bytes in a ResultSubmit and a SlotResult must hash apart, so
	// one signature can never stand in for the other.
	slot := SlotHash(&agentpb.SlotResult{AssignmentId: "a", Outcome: agentpb.ResultOutcome_RESULT_OUTCOME_PASS})
	task := Hash(&agentpb.ResultSubmit{TaskId: "a", Outcome: agentpb.ResultOutcome_RESULT_OUTCOME_PASS})
	if bytes.Equal(slot, task) {
		t.Error("slot and task canonical hashes collide")
	}
}

func TestSlotHashSeparatesIDFromSlot(t *testing.T) {
	a := SlotHash(&agentpb.SlotResult{AssignmentId: "ab", Slot: 1})
	b := SlotHash(&agentpb.SlotResult{AssignmentId: "a", Slot: 1})
	if bytes.Equal(a, b) {
		t.Error("different assignment IDs hash alike")
	}
}

func TestVerifySlotRejectsMalformedKey(t *testing.T) {
	if VerifySlot([]byte("short"), &agentpb.SlotResult{}) {
		t.Error("a malformed key verified")
	}
}
