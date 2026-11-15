package main

// The App pins SHA256 fingerprints of sshd's host public keys. On Unix they
// come from ssh-keyscan, on Windows from the .pub files with ssh-keyscan as the
// fallback for a filtered administrator token; both go through this parser, so
// the two paths can never disagree about the pin format.

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSSHPinsFromKeyscanOutputMatchesTheAppPin(t *testing.T) {
	blob := base64.StdEncoding.EncodeToString([]byte("host-key-blob"))
	hash := sha256.Sum256([]byte("host-key-blob"))
	want := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
	output := []byte("# 127.0.0.1:22 SSH-2.0-OpenSSH_for_Windows_9.5\r\n" +
		"127.0.0.1 ecdsa-sha2-nistp256 " + blob + "\n" +
		"127.0.0.1 ecdsa-sha2-nistp256 " + blob + "\n" +
		"not a key line\n")
	pins, err := sshPinsFromKeyscanOutput(output)
	if err != nil || len(pins) != 1 || pins[0] != want {
		t.Fatalf("pins = %v, %v; want [%s]", pins, err, want)
	}
	for _, empty := range [][]byte{nil, []byte("\n"), []byte("127.0.0.1 ssh-ed25519 !!!notbase64\n")} {
		if _, err := sshPinsFromKeyscanOutput(empty); err == nil || !strings.Contains(err.Error(), "ssh_pair_local_ssh_unavailable") {
			t.Fatalf("sshPinsFromKeyscanOutput(%q) = %v, want ssh_pair_local_ssh_unavailable", empty, err)
		}
	}
}