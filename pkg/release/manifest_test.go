package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// signed builds a manifest, signs it, and returns the public key (base64), the
// manifest bytes, and the detached signature (base64) — the three inputs Verify
// takes.
func signed(t *testing.T, m Manifest) (pubB64 string, manifestBytes []byte, sigB64 string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	manifestBytes, err = Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sig := ed25519.Sign(priv, manifestBytes)
	return base64.StdEncoding.EncodeToString(pub), manifestBytes, base64.StdEncoding.EncodeToString(sig)
}

func sampleManifest() Manifest {
	return Manifest{
		Version: "0.2.0",
		Artifacts: map[string]Artifact{
			"linux/amd64": {Filename: "meshcheck-agent_linux_amd64.tar.gz", SHA256: "abc123"},
			"linux/arm64": {Filename: "meshcheck-agent_linux_arm64.tar.gz", SHA256: "def456"},
		},
	}
}

func TestVerifyAcceptsGoodSignature(t *testing.T) {
	pub, body, sig := signed(t, sampleManifest())
	if err := Verify(pub, body, sig); err != nil {
		t.Fatalf("Verify rejected a valid signature: %v", err)
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	pub, body, sig := signed(t, sampleManifest())
	body = append(body, ' ') // flip one byte
	if err := Verify(pub, body, sig); err == nil {
		t.Fatal("Verify accepted a tampered manifest")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, body, sig := signed(t, sampleManifest())
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	if err := Verify(base64.StdEncoding.EncodeToString(otherPub), body, sig); err == nil {
		t.Fatal("Verify accepted a signature from a different key")
	}
}

func TestVerifyRejectsGarbageInputs(t *testing.T) {
	pub, body, _ := signed(t, sampleManifest())
	if err := Verify("not-base64!", body, "also-bad"); err == nil {
		t.Fatal("Verify accepted an undecodable public key")
	}
	if err := Verify(pub, body, "not-base64!"); err == nil {
		t.Fatal("Verify accepted an undecodable signature")
	}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	m := sampleManifest()
	body, err := Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Version != m.Version || len(got.Artifacts) != len(m.Artifacts) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, m)
	}
	if got.Artifacts["linux/amd64"].SHA256 != "abc123" {
		t.Fatalf("artifact lost in round trip: %+v", got.Artifacts)
	}
}

func TestMarshalIsDeterministic(t *testing.T) {
	// Map key order must not change the signed bytes, or signatures would be
	// unverifiable across processes.
	a, _ := Marshal(sampleManifest())
	b, _ := Marshal(sampleManifest())
	if string(a) != string(b) {
		t.Fatal("Marshal is not deterministic")
	}
}
