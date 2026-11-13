package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var platformsForTest = []string{"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64"}

func buildTool(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "release")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func binaries(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, p := range platformsForTest {
		if err := os.WriteFile(filepath.Join(dir, p), []byte("bin-"+p), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func run(bin, keys, in, out, seq string) (string, error) {
	b, err := exec.Command(bin, "--keys", keys, "--binaries", in, "--out", out, "--sequence", seq, "--bootstrap-script", filepath.Join("..", "..", "install.sh")).CombinedOutput()
	return string(b), err
}

// CI holds every key except root; root.json is public. Signing must work
// without root.key and refuse keys root.json does not trust.
func TestSignsWithoutRootKeyAndRejectsUntrustedKey(t *testing.T) {
	bin, in := buildTool(t), binaries(t)
	keys := filepath.Join(t.TempDir(), "keys")
	if out, err := run(bin, keys, in, filepath.Join(t.TempDir(), "r1"), "2026110401"); err != nil {
		t.Fatalf("bootstrap: %v\n%s", err, out)
	}
	if err := os.Remove(filepath.Join(keys, "root.key")); err != nil {
		t.Fatal(err)
	}
	if out, err := run(bin, keys, in, filepath.Join(t.TempDir(), "r2"), "2026110402"); err != nil {
		t.Fatalf("sign without root key: %v\n%s", err, out)
	}
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	if err := os.WriteFile(filepath.Join(keys, "targets.key"), wrong, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(bin, keys, in, filepath.Join(t.TempDir(), "r3"), "2026110403")
	if err == nil || !strings.Contains(out, "targets key does not match root.json") {
		t.Fatalf("want untrusted-key refusal, got err=%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(keys, "root.key")); err == nil {
		t.Fatal("root key must never be regenerated")
	}
}
