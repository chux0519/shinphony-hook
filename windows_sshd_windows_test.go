//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The status JSON is what the site script and the App read; its keys are part of
// the contract, so they are pinned here.
func TestWindowsSSHDStatusJSONKeys(t *testing.T) {
	status, err := collectWindowsSSHDStatus()
	if err != nil {
		t.Skipf("windows-sshd status needs PowerShell on this machine: %v", err)
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"installed", "running", "startType", "firewall", "isAdmin", "elevated", "keyFile"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("status JSON is missing %q: %s", key, raw)
		}
	}
	firewall, ok := decoded["firewall"].(map[string]any)
	if !ok {
		t.Fatalf("firewall is not an object: %s", raw)
	}
	for _, key := range []string{"exists", "enabled", "profile"} {
		if _, ok := firewall[key]; !ok {
			t.Fatalf("firewall JSON is missing %q: %s", key, raw)
		}
	}
	if status.IsAdmin != windowsIsAdministrator() || status.Elevated != windowsIsElevated() {
		t.Fatal("status must report this process's own identity")
	}
	if status.Installed && status.StartType == "" {
		t.Fatal("an installed sshd service must report its start type")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".ssh", "authorized_keys")
	if _, _, shared := sshKeyTargetForAccount(windowsIsAdministrator(), windowsSSHDConfig(), home, sshdConfigDirectory()); shared {
		want = filepath.Join(sshdConfigDirectory(), "administrators_authorized_keys")
	}
	if status.KeyFile != want {
		t.Fatalf("keyFile = %q, want %q", status.KeyFile, want)
	}
}

func TestWindowsSSHDCLIRejectsUsage(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{nil, {}, {"start"}, {"prepare"}, {"status", "extra"}, {"prepare-keys", "extra"}, {"--help"}} {
		if err := windowsSSHDCLI(args, &out); err == nil || !strings.Contains(err.Error(), "usage: windows-sshd") {
			t.Fatalf("windowsSSHDCLI(%v) = %v, want the usage sentence", args, err)
		}
	}
	if out.Len() != 0 {
		t.Fatal("a usage error must not print a status line")
	}
}

// enable only ever changes the machine when the process is elevated. A normal
// (non-elevated) run must say so in one sentence with an action instead of
// calling PowerShell, and must leave the service untouched.
func TestWindowsSSHDEnableNeedsElevation(t *testing.T) {
	if windowsIsElevated() {
		t.Skip("this process is elevated; run the test exe from a normal PowerShell prompt")
	}
	before, err := collectWindowsSSHDStatus()
	if err != nil {
		t.Skipf("windows-sshd status needs PowerShell on this machine: %v", err)
	}
	var out bytes.Buffer
	err = windowsSSHDCLI([]string{"enable"}, &out)
	if err == nil || !strings.Contains(err.Error(), "administrator permission") {
		t.Fatalf("enable without elevation = %v, want the administrator sentence", err)
	}
	if out.Len() != 0 {
		t.Fatal("a refused enable must not print a status line")
	}
	after, err := collectWindowsSSHDStatus()
	if err != nil {
		t.Fatal(err)
	}
	if before.Installed != after.Installed || before.Running != after.Running || before.StartType != after.StartType {
		t.Fatal("a refused enable changed the sshd service")
	}
}

// prepare-keys only creates the shared administrator key file, which needs
// administrator rights. A normal run says so and creates nothing, so a broken
// elevation can never leave a file in ProgramData with the wrong owner.
func TestWindowsSSHDPrepareKeysNeedsElevation(t *testing.T) {
	if windowsIsElevated() {
		t.Skip("elevated runs may create ProgramData\\ssh\\administrators_authorized_keys")
	}
	var out bytes.Buffer
	err := windowsSSHDCLI([]string{"prepare-keys"}, &out)
	if err == nil || !strings.Contains(err.Error(), "administrator permission") {
		t.Fatalf("prepare-keys without elevation = %v, want the administrator sentence", err)
	}
	if out.Len() != 0 {
		t.Fatal("a refused prepare-keys must not print a line")
	}
}
