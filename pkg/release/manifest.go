// SPDX-License-Identifier: Apache-2.0

// Package release defines the agent release manifest and the Ed25519 signature
// over it. The build pipeline (cmd/release-sign, run offline) produces a
// manifest plus a detached signature; the agent (cmd/agent) verifies both
// against a public key baked into its binary before replacing itself. Keeping
// the type and the verify path here lets both sides — and their tests — share
// one definition.
package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Artifact is one downloadable agent build: the file (relative to the manifest
// URL) and the SHA-256 the agent must see over the downloaded bytes.
type Artifact struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"` // lowercase hex
}

// Manifest names the current release and its per-platform artifacts. Artifacts
// is keyed by "os/arch" (runtime.GOOS+"/"+runtime.GOARCH), e.g. "linux/amd64".
type Manifest struct {
	Version   string              `json:"version"`
	Artifacts map[string]Artifact `json:"artifacts"`
}

// Marshal renders the manifest to the canonical bytes that get signed and
// served. json.Marshal sorts map keys, so the output is deterministic for a
// given manifest. The signature is taken over exactly these bytes, and the
// agent verifies exactly the bytes it downloads, so there is no canonicalization
// ambiguity between the two sides.
func Marshal(m Manifest) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// Parse decodes manifest bytes into a Manifest.
func Parse(data []byte) (Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	return m, nil
}

// DecodePublicKey decodes a base64 Ed25519 public key (the form baked into the
// agent binary and committed at deploy/release-pubkey.b64).
func DecodePublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode release public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("release public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Verify checks a detached base64 signature over manifestBytes against the
// base64-encoded public key. It returns nil only when the signature is valid.
func Verify(pubB64 string, manifestBytes []byte, sigB64 string) error {
	pub, err := DecodePublicKey(pubB64)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, manifestBytes, sig) {
		return errors.New("manifest signature does not verify against the release public key")
	}
	return nil
}
