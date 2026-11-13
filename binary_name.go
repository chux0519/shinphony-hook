package main

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

const (
	commandName   = "shinphony-hook"
	managedPrefix = commandName + "-"
	legacyPrefix  = "agent-"
	// Persistent identities intentionally survive the executable rename. Moving
	// these would strand pairing/update state and register a second daemon.
	stateDirectoryName = ".shinphony-agent"
	// credentialsDirectoryName holds the phone pairing profiles the notifier uses.
	credentialsDirectoryName = ".shinphony-notify"
)

// managedBinaryDigest recognises only immutable, SHA256-addressed copies.
// Legacy copies remain callable while installed hooks transition to the new
// executable; a plain PATH command must not infer its state from its directory.
func managedBinaryDigest(name string) (string, bool) {
	name = strings.TrimSuffix(filepath.Base(name), ".exe")
	for _, prefix := range []string{managedPrefix, legacyPrefix} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		digest := strings.TrimPrefix(name, prefix)
		if len(digest) != sha256.Size*2 || strings.ToLower(digest) != digest {
			return "", false
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return "", false
		}
		return digest, true
	}
	return "", false
}

func matchesManagedBinary(name string, data []byte) bool {
	digest, ok := managedBinaryDigest(name)
	sum := sha256.Sum256(data)
	return ok && digest == hex.EncodeToString(sum[:])
}
