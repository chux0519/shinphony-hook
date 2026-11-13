//go:build darwin || linux

package main

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func testP256SSHKey() string {
	field := func(b []byte) []byte {
		r := make([]byte, 4+len(b))
		binary.BigEndian.PutUint32(r, uint32(len(b)))
		copy(r[4:], b)
		return r
	}
	curve := elliptic.P256()
	point := elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy)
	wire := append(field([]byte("ecdsa-sha2-nistp256")), field([]byte("nistp256"))...)
	wire = append(wire, field(point)...)
	return "ecdsa-sha2-nistp256 " + base64.StdEncoding.EncodeToString(wire)
}
func keyRequest() sshKeyRequest {
	return sshKeyRequest{ID: "se-p256:12345678-1234-1234-1234-123456789abc", PublicKey: testP256SSHKey()}
}

func TestSSHKeyListDoesNotCreateLockOrJournal(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := manageSSHKey(home, "list", sshKeyRequest{}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("list modified the SSH directory")
	}
}

func TestSSHKeyInstallPreservesAndRevokesOnlyOwnedLine(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "authorized_keys")
	original := []byte("# user notes\r\nssh-ed25519 AAAA existing-device")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	req := keyRequest()
	for range 2 {
		if _, err := manageSSHKey(home, "install", req); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(path)
	line := req.PublicKey + " shinphony:" + req.ID + "\n"
	if string(data) != string(original)+"\n"+line {
		t.Fatalf("existing content changed or duplicate key: %q", data)
	}
	for range 2 {
		if _, err := manageSSHKey(home, "revoke", sshKeyRequest{ID: req.ID}); err != nil {
			t.Fatal(err)
		}
	}
	data, _ = os.ReadFile(path)
	if string(data) != string(original)+"\n" {
		t.Fatalf("removed unrelated content: %q", data)
	}
}

func TestSSHKeyRejectsUnsafePathsAndKeys(t *testing.T) {
	for _, scenario := range []string{"directory_symlink", "file_symlink", "hard_link", "permissions", "options", "bad_point"} {
		t.Run(scenario, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, ".ssh")
			req := keyRequest()
			if scenario == "directory_symlink" {
				other := t.TempDir()
				if err := os.Symlink(other, dir); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(home, "untouched")
				if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "authorized_keys")
				switch scenario {
				case "file_symlink":
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				case "hard_link":
					if err := os.Link(target, path); err != nil {
						t.Fatal(err)
					}
				case "permissions":
					if err := os.WriteFile(path, []byte("unchanged"), 0644); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				case "options":
					req.PublicKey = "command=\"malicious\" " + req.PublicKey
				case "bad_point":
					raw, _ := base64.StdEncoding.DecodeString(strings.Split(req.PublicKey, " ")[1])
					for i := len(raw) - 64; i < len(raw); i++ {
						raw[i] = 0
					}
					req.PublicKey = "ecdsa-sha2-nistp256 " + base64.StdEncoding.EncodeToString(raw)
				}
			}
			if _, err := manageSSHKey(home, "install", req); err == nil {
				t.Fatal("unsafe key installation accepted")
			}
			if data, err := os.ReadFile(filepath.Join(home, "untouched")); err == nil && string(data) != "unchanged" {
				t.Fatal("changed unrelated target")
			}
		})
	}
}

func TestSSHKeyResumesPreparedInstallAndRefusesUnownedKey(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	req := keyRequest()
	fp, _ := validateP256PublicKey(req.PublicKey)
	journal := sshKeyJournal{Schema: 1, Keys: map[string]sshKeyRecord{req.ID: {ID: req.ID, PublicKey: req.PublicKey, Fingerprint: fp, State: "installing"}}}
	raw, _ := json.Marshal(journal)
	if err := os.WriteFile(filepath.Join(dir, ".shinphony-keys.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte(req.PublicKey+" shinphony:"+req.ID+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manageSSHKey(home, "install", req); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "authorized_keys"))
	if strings.Count(string(data), req.PublicKey) != 1 {
		t.Fatal("recovery duplicated public key")
	}
	// If somebody changes the managed comment, never claim that revocation worked.
	if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte(req.PublicKey+" manually-changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manageSSHKey(home, "revoke", sshKeyRequest{ID: req.ID}); err == nil {
		t.Fatal("revoked an unmanaged copy")
	}
}

func TestSSHKeyPreviewDoesNotCreateFiles(t *testing.T) {
	home := t.TempDir()
	if _, err := manageSSHKey(home, "preview", keyRequest()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatal("preview changed the computer", err)
	}
}

func TestSSHKeyWriteDetectsExternalChange(t *testing.T) {
	home := t.TempDir()
	dir, err := sshKeyDirectory(home, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	path := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(path, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := sshKeyRead(dir, "authorized_keys")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed outside this installer\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := sshKeyWrite(dir, "authorized_keys", []byte("replacement\n"), snapshot); err == nil {
		t.Fatal("overwrote external changes")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "changed outside this installer\n" {
		t.Fatal("lost external changes")
	}
}
