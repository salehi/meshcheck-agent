// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// loadOrCreateKey returns the Node's Ed25519 signing key, generating and
// persisting a fresh one the first time. The key must be stable for the life
// of the Node: the platform records the public half on the first connection
// and treats it as immutable, so a regenerated key would make every later
// Result fail signature verification.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("signing key file %q is corrupt (%d bytes)", path, len(data))
		}
		return ed25519.PrivateKey(data), nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	// First run for this Node — mint and persist a keypair.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create key directory: %w", err)
		}
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, fmt.Errorf("persist signing key: %w", err)
	}
	return priv, nil
}
