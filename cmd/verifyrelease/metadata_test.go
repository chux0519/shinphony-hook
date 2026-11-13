package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type metadataSet struct {
	root, timestamp, snapshot, targets []byte
	hashes                             map[string]string
}

func signer(t *testing.T, key ed25519.PrivateKey) signature.Signer {
	t.Helper()
	s, err := signature.LoadSigner(key, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// buildMetadata mirrors cmd/release: one key per role, all trusted by a root
// signed with the root key.
func buildMetadata(t *testing.T, seq int64, expiry time.Time, mutate func(*metadata.Metadata[metadata.TargetsType])) metadataSet {
	t.Helper()
	keys := map[string]ed25519.PrivateKey{}
	root := metadata.Root(expiry)
	root.Signed.ConsistentSnapshot = true
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[role] = key
		pub, err := metadata.KeyFromPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Signed.AddKey(pub, role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := root.Sign(signer(t, keys["root"])); err != nil {
		t.Fatal(err)
	}
	rootBytes, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	targets := metadata.Targets(expiry)
	targets.Signed.Version = seq
	hashes := map[string]string{}
	for _, platform := range platforms {
		data := []byte("binary-" + platform)
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])
		hashes[platform] = h
		target, err := metadata.TargetFile().FromBytes("agent/"+platform, data, "sha256")
		if err != nil {
			t.Fatal(err)
		}
		custom, _ := json.Marshal(map[string]any{"sequence": seq, "apiVersion": 2, "platform": platform})
		raw := json.RawMessage(custom)
		target.Custom = &raw
		targets.Signed.Targets["agent/"+platform] = target
	}
	if mutate != nil {
		mutate(targets)
	}
	if _, err := targets.Sign(signer(t, keys["targets"])); err != nil {
		t.Fatal(err)
	}
	targetsBytes, err := targets.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	snapshot := metadata.Snapshot(expiry)
	snapshot.Signed.Version = seq
	tf := metadata.MetaFile(seq)
	th := sha256.Sum256(targetsBytes)
	tf.Length = int64(len(targetsBytes))
	tf.Hashes = metadata.Hashes{"sha256": th[:]}
	snapshot.Signed.Meta["targets.json"] = tf
	if _, err := snapshot.Sign(signer(t, keys["snapshot"])); err != nil {
		t.Fatal(err)
	}
	snapshotBytes, err := snapshot.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	timestamp := metadata.Timestamp(expiry)
	timestamp.Signed.Version = seq
	sf := metadata.MetaFile(seq)
	sh := sha256.Sum256(snapshotBytes)
	sf.Length = int64(len(snapshotBytes))
	sf.Hashes = metadata.Hashes{"sha256": sh[:]}
	timestamp.Signed.Meta["snapshot.json"] = sf
	if _, err := timestamp.Sign(signer(t, keys["timestamp"])); err != nil {
		t.Fatal(err)
	}
	timestampBytes, err := timestamp.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return metadataSet{root: rootBytes, timestamp: timestampBytes, snapshot: snapshotBytes, targets: targetsBytes, hashes: hashes}
}

func TestVerifyMetadataSet(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	set := buildMetadata(t, 2026111303, now.Add(30*24*time.Hour), nil)
	summary, err := verifyMetadataSet(set.root, set.timestamp, set.snapshot, set.targets, now)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Sequence != 2026111303 {
		t.Fatalf("sequence %d", summary.Sequence)
	}
	for platform, hash := range set.hashes {
		if summary.Targets[platform].SHA256 != hash {
			t.Errorf("%s hash %q, want %q", platform, summary.Targets[platform].SHA256, hash)
		}
	}
}

func TestVerifyMetadataSetRejects(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	fresh := func() metadataSet { return buildMetadata(t, 2026111303, now.Add(30*24*time.Hour), nil) }

	cases := []struct {
		name   string
		mutate func(*metadataSet)
		now    time.Time
	}{
		{"expired timestamp", func(s *metadataSet) {}, now.Add(31 * 24 * time.Hour)},
		{"tampered targets", func(s *metadataSet) {
			s.targets = append([]byte{}, s.targets...)
			s.targets[0] ^= 0x01
		}, now},
		{"mismatched snapshot length", func(s *metadataSet) { s.snapshot = append(s.snapshot, '\n') }, now},
		{"missing platform", func(s *metadataSet) {
			s2 := buildMetadata(t, 2026111303, now.Add(30*24*time.Hour), func(targets *metadata.Metadata[metadata.TargetsType]) {
				delete(targets.Signed.Targets, "agent/windows-arm64")
			})
			*s = s2
		}, now},
		{"wrong api version", func(s *metadataSet) {
			s2 := buildMetadata(t, 2026111303, now.Add(30*24*time.Hour), func(targets *metadata.Metadata[metadata.TargetsType]) {
				custom, _ := json.Marshal(map[string]any{"apiVersion": 1, "platform": "linux-amd64"})
				raw := json.RawMessage(custom)
				targets.Signed.Targets["agent/linux-amd64"].Custom = &raw
			})
			*s = s2
		}, now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := fresh()
			tc.mutate(&set)
			if _, err := verifyMetadataSet(set.root, set.timestamp, set.snapshot, set.targets, tc.now); err == nil {
				t.Fatal("metadata accepted")
			}
		})
	}
}

func TestVerifyMetadataSetRejectsAnotherRoot(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	trusted := buildMetadata(t, 2026111303, now.Add(30*24*time.Hour), nil)
	other := buildMetadata(t, 2026111303, now.Add(30*24*time.Hour), nil)
	if _, err := verifyMetadataSet(trusted.root, other.timestamp, other.snapshot, other.targets, now); err == nil {
		t.Fatal("metadata from another root accepted")
	}
}
