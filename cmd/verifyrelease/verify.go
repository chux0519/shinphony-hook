package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// Platforms the App and updater know about; a release must ship exactly these.
var platforms = []string{"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64"}

var sha256Hex = regexp.MustCompile(`^[a-f0-9]{64}$`)

type target struct {
	SHA256 string `json:"sha256"`
	Length int64  `json:"length"`
	URL    string `json:"url"`
}

type payload struct {
	SSHPairing    int               `json:"sshPairing"`
	BootstrapHash string            `json:"bootstrapHash"`
	Schema        int               `json:"schema"`
	Sequence      int64             `json:"sequence"`
	Expires       string            `json:"expires"`
	Targets       map[string]target `json:"targets"`
}

// Summary lists every file to publish, relative to the release directory.
type Summary struct {
	Sequence int64    `json:"sequence"`
	Expires  string   `json:"expires"`
	Targets  []string `json:"targets"`
	Metadata []string `json:"metadata"`
	Other    []string `json:"other"`
}

func (s Summary) JSON() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Verify checks signature, sequence, expiry, target hashes/lengths/URLs and
// the file set of a release directory.
func Verify(dir, pinnedKey, origin string, after int64) (Summary, error) {
	var s Summary
	key, err := base64.StdEncoding.DecodeString(pinnedKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return s, errors.New("pinned key is not a base64 ed25519 public key")
	}
	if err := noSymlinks(dir); err != nil {
		return s, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return s, fmt.Errorf("manifest: %w", err)
	}
	var envelope struct{ Payload, Signature string }
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return s, fmt.Errorf("manifest envelope: %w", err)
	}
	body, err1 := base64.StdEncoding.DecodeString(envelope.Payload)
	sig, err2 := base64.StdEncoding.DecodeString(envelope.Signature)
	if err1 != nil || err2 != nil {
		return s, errors.New("manifest envelope is not base64")
	}
	if !ed25519.Verify(ed25519.PublicKey(key), body, sig) {
		return s, errors.New("manifest signature does not match the pinned bootstrap key")
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return s, fmt.Errorf("manifest payload: %w", err)
	}
	if p.Schema != 1 {
		return s, fmt.Errorf("unsupported manifest schema %d", p.Schema)
	}
	if p.Sequence <= after {
		return s, fmt.Errorf("sequence %d is not newer than published %d", p.Sequence, after)
	}
	expires, err := time.Parse(time.RFC3339, p.Expires)
	if err != nil || !expires.After(time.Now().Add(24*time.Hour)) {
		return s, fmt.Errorf("manifest expires %q (must be valid and at least a day away)", p.Expires)
	}
	if published, err := os.ReadFile(filepath.Join(dir, "bootstrap-public-key.txt")); err == nil {
		if string(trim(published)) != pinnedKey {
			return s, errors.New("bootstrap-public-key.txt differs from the pinned key")
		}
	}
	if len(p.Targets) != len(platforms) {
		return s, fmt.Errorf("expected %d platform targets, got %d", len(platforms), len(p.Targets))
	}
	for _, platform := range platforms {
		t, ok := p.Targets[platform]
		if !ok {
			return s, fmt.Errorf("missing target %s", platform)
		}
		if !sha256Hex.MatchString(t.SHA256) || t.Length <= 0 || t.Length > 64<<20 {
			return s, fmt.Errorf("invalid target entry for %s", platform)
		}
		name := "targets/agent/" + t.SHA256 + "." + platform
		if want := origin + "/agent/" + name; t.URL != want {
			return s, fmt.Errorf("target %s URL %q, want %q", platform, t.URL, want)
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return s, fmt.Errorf("target file %s: %w", name, err)
		}
		sum := sha256.Sum256(data)
		if int64(len(data)) != t.Length || hex.EncodeToString(sum[:]) != t.SHA256 {
			return s, fmt.Errorf("target %s does not match its signed hash/length", platform)
		}
		s.Targets = append(s.Targets, name)
	}
	seq := strconv.FormatInt(p.Sequence, 10)
	for _, m := range []string{"root.json", "1.root.json", "timestamp.json", "snapshot.json", "targets.json", seq + ".snapshot.json", seq + ".targets.json"} {
		if _, err := os.Stat(filepath.Join(dir, "metadata", m)); err != nil {
			return s, fmt.Errorf("missing metadata/%s", m)
		}
		s.Metadata = append(s.Metadata, "metadata/"+m)
	}
	known := map[string]bool{"manifest.json": true}
	if p.SSHPairing == 1 || p.BootstrapHash != "" {
		if !sha256Hex.MatchString(p.BootstrapHash) {
			return s, errors.New("invalid bootstrap hash")
		}
		script, err := os.ReadFile(filepath.Join(dir, "install.sh"))
		if err != nil || len(script) == 0 || len(script) > 65536 {
			return s, errors.New("missing or invalid bootstrap script")
		}
		hash := sha256.Sum256(script)
		if hex.EncodeToString(hash[:]) != p.BootstrapHash {
			return s, errors.New("bootstrap script hash mismatch")
		}
		known["install.sh"] = true
		s.Other = append(s.Other, "install.sh")
	}
	for _, f := range append(append([]string{}, s.Targets...), s.Metadata...) {
		known[f] = true
	}
	for _, optional := range []string{"bootstrap-public-key.txt", "update-policy.json"} {
		if _, err := os.Stat(filepath.Join(dir, optional)); err == nil {
			known[optional] = true
			s.Other = append(s.Other, optional)
		}
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		if !known[filepath.ToSlash(rel)] {
			return fmt.Errorf("unexpected file %s", rel)
		}
		return nil
	})
	if err != nil {
		return s, err
	}
	s.Sequence, s.Expires = p.Sequence, p.Expires
	sort.Strings(s.Other)
	return s, nil
}

func noSymlinks(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlink not allowed: %s", path)
		}
		return nil
	})
}

func trim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
