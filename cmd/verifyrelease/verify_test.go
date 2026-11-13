package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testOrigin = "https://downloads.example.test"

type fixture struct {
	dir string
	pub string
	key ed25519.PrivateKey
}

func TestBootstrapScriptMustMatchSignedHash(t *testing.T) {
	script := []byte("#!/bin/sh\nexit 0\n")
	hash := sha256.Sum256(script)
	f := makeRelease(t, 2026110601, func(p map[string]any) { p["sshPairing"] = 1; p["bootstrapHash"] = hex.EncodeToString(hash[:]) })
	if _, err := Verify(f.dir, f.pub, testOrigin, 0); err == nil {
		t.Fatal("missing bootstrap accepted")
	}
	write(t, filepath.Join(f.dir, "install.sh"), script)
	if _, err := Verify(f.dir, f.pub, testOrigin, 0); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(f.dir, "install.sh"), []byte("tampered"))
	if _, err := Verify(f.dir, f.pub, testOrigin, 0); err == nil {
		t.Fatal("tampered bootstrap accepted")
	}
}

func makeRelease(t *testing.T, seq int64, mutate func(p map[string]any)) fixture {
	t.Helper()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	targets := map[string]any{}
	for _, platform := range platforms {
		data := []byte("binary-" + platform + "-" + strconv.FormatInt(seq, 10))
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])
		name := "targets/agent/" + h + "." + platform
		write(t, filepath.Join(dir, name), data)
		targets[platform] = map[string]any{"sha256": h, "length": len(data), "url": testOrigin + "/agent/" + name}
	}
	s := strconv.FormatInt(seq, 10)
	for _, m := range []string{"root.json", "1.root.json", "timestamp.json", "snapshot.json", "targets.json", s + ".snapshot.json", s + ".targets.json"} {
		write(t, filepath.Join(dir, "metadata", m), []byte("{}"))
	}
	p := map[string]any{"schema": 1, "sequence": seq, "expires": time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339), "targets": targets}
	if mutate != nil {
		mutate(p)
	}
	body, _ := json.Marshal(p)
	env, _ := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(body), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, body))})
	write(t, filepath.Join(dir, "manifest.json"), env)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	write(t, filepath.Join(dir, "bootstrap-public-key.txt"), []byte(pubB64))
	return fixture{dir: dir, pub: pubB64, key: key}
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func expectReject(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want rejection containing %q, got %v", want, err)
	}
}

func TestValidReleasePasses(t *testing.T) {
	f := makeRelease(t, 2026110401, nil)
	s, err := Verify(f.dir, f.pub, testOrigin, 2026110201)
	if err != nil {
		t.Fatal(err)
	}
	if s.Sequence != 2026110401 || len(s.Targets) != 6 || len(s.Metadata) != 7 {
		t.Fatalf("summary %+v", s)
	}
}

func TestRejectsKeyNotPinned(t *testing.T) {
	f := makeRelease(t, 2026110401, nil)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	_, err := Verify(f.dir, base64.StdEncoding.EncodeToString(other), testOrigin, 0)
	expectReject(t, err, "pinned bootstrap key")
}

func TestRejectsRollback(t *testing.T) {
	f := makeRelease(t, 2026110401, nil)
	_, err := Verify(f.dir, f.pub, testOrigin, 2026110401)
	expectReject(t, err, "not newer")
}

func TestRejectsTamperedBinary(t *testing.T) {
	f := makeRelease(t, 2026110401, nil)
	matches, _ := filepath.Glob(filepath.Join(f.dir, "targets/agent/*.linux-amd64"))
	write(t, matches[0], []byte("evil"))
	_, err := Verify(f.dir, f.pub, testOrigin, 0)
	expectReject(t, err, "does not match its signed hash")
}

func TestRejectsWrongOrigin(t *testing.T) {
	f := makeRelease(t, 2026110401, nil)
	_, err := Verify(f.dir, f.pub, "https://downloads.potafree.net", 0)
	expectReject(t, err, "URL")
}

func TestRejectsUnexpectedFile(t *testing.T) {
	f := makeRelease(t, 2026110401, nil)
	write(t, filepath.Join(f.dir, "targets/agent/extra.sh"), []byte("x"))
	_, err := Verify(f.dir, f.pub, testOrigin, 0)
	expectReject(t, err, "unexpected file")
}

func TestRejectsNearExpiry(t *testing.T) {
	f := makeRelease(t, 2026110401, func(p map[string]any) {
		p["expires"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	})
	_, err := Verify(f.dir, f.pub, testOrigin, 0)
	expectReject(t, err, "expires")
}

func TestRejectsMissingPlatform(t *testing.T) {
	f := makeRelease(t, 2026110401, func(p map[string]any) {
		delete(p["targets"].(map[string]any), "windows-arm64")
	})
	_, err := Verify(f.dir, f.pub, testOrigin, 0)
	expectReject(t, err, "platform targets")
}

// The real most recent local release, verified with the key the App pins.
func TestLocalPublishedReleaseWithAppPinnedKey(t *testing.T) {
	dir := filepath.Join("..", "..", "build", "releases", "2026110201")
	if _, err := os.Stat(dir); err != nil {
		t.Skip("local signed release not present")
	}
	pinned, err := os.ReadFile(filepath.Join("..", "..", "deploy", "bootstrap-public-key.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir, strings.TrimSpace(string(pinned)), "https://downloads.potafree.net", 2026110101); err != nil {
		t.Fatal(err)
	}
}
