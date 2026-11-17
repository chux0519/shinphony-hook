//go:build windows

package main

// TF 160: pairing on a Windows administrator account reached the elevated
// window, flashed, and then said "Could not start Shinphony Hook; set it up from
// Shinphony." with no step named. The cause is ownership: an elevated
// administrator process creates folders owned by BUILTIN\Administrators, and
// prepareDir only accepted the user's own SID, so every later non-elevated run
// failed with unsafe_state_directory.
//
// These tests pin the three parts of the fix: the owner rule (an administrator
// account accepts an Administrators owner, a standard user does not), the list of
// paths an elevated step may write, and the timeout that names the folder from
// the worker's own log.

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func fixtureSID(t *testing.T, value string) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid(value)
	if err != nil {
		t.Fatalf("SID %q: %v", value, err)
	}
	return sid
}

// The SID table: which owner a private path may have for this account.
func TestWindowsPrivateOwnerRule(t *testing.T) {
	account := fixtureSID(t, "S-1-5-21-1-2-3-1001")
	other := fixtureSID(t, "S-1-5-21-1-2-3-1002")
	administrators := fixtureSID(t, "S-1-5-32-544")
	system := fixtureSID(t, "S-1-5-18")
	cases := []struct {
		name          string
		owner         *windows.SID
		administrator bool
		want          bool
	}{
		{"the account's own SID", account, false, true},
		{"the account's own SID when the account is an administrator", account, true, true},
		// An elevated administrator process creates folders owned by the group.
		{"Administrators, administrator", administrators, true, true},
		// A standard user must never accept a folder it cannot own itself.
		{"Administrators, standard user", administrators, false, false},
		{"SYSTEM", system, true, false},
		{"another account", other, true, false},
		{"no owner", nil, true, false},
	}
	for _, c := range cases {
		if got := windowsPrivateOwnerAccepted(c.owner, account, c.administrator); got != c.want {
			t.Fatalf("%s: windowsPrivateOwnerAccepted = %v, want %v", c.name, got, c.want)
		}
	}
}

// Every path an elevated step may create or change: the shared administrator key
// file and its neighbours under ProgramData\ssh, plus the request and log files
// the non-elevated pairing created before the UAC prompt. Never the profile.
func TestWindowsElevatedWritesStayOutsideTheProfile(t *testing.T) {
	home := `C:\Users\you`
	temp := filepath.Join(home, `AppData`, `Local`, `Temp`, `shinphony-key-1`)
	dir, file := windowsKeyDirectory(true, home)
	if dir != sshdConfigDirectory() || file != "administrators_authorized_keys" {
		t.Fatalf("administrator key target = %q\\%q", dir, file)
	}
	if strings.HasPrefix(strings.ToLower(dir), strings.ToLower(home)) {
		t.Fatal("the administrator key directory is inside the profile")
	}
	// The account's own key never comes from an elevated step: it is written in
	// the user's own window.
	if userDir, userFile := windowsKeyDirectory(false, home); userDir != filepath.Join(home, ".ssh") || userFile != "authorized_keys" {
		t.Fatalf("user key target = %q\\%q", userDir, userFile)
	}
	writes := windowsElevatedWriteList(home, temp)
	if len(writes) == 0 {
		t.Fatal("no elevated write list")
	}
	sshDir := strings.ToLower(sshdConfigDirectory()) + `\`
	tempDir := strings.ToLower(temp) + `\`
	for _, path := range writes {
		lower := strings.ToLower(path)
		switch {
		case strings.HasPrefix(lower, sshDir), strings.HasPrefix(lower, tempDir):
		default:
			t.Fatalf("elevated write %q is outside ProgramData\\ssh and the pairing's temp directory", path)
		}
	}
}

// The elevated script itself creates no file: it reads the request the pairing
// wrote, pipes it into `keys install`, and appends to the log the pairing
// created. Nothing in it sets an owner or a descriptor.
func TestWindowsElevatedKeyInstallWritesOnlyItsLog(t *testing.T) {
	script := windowsElevatedKeyInstallScript(
		`C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe`,
		`C:\Users\you\AppData\Local\Temp\shinphony-key-1\request.json`,
		`C:\Users\you\AppData\Local\Temp\shinphony-key-1\elevated.log`,
		"S-1-5-21-1-2-3-1001")
	for _, forbidden := range []string{"New-Item", "Set-Content", "Add-Content", "Set-Acl", "SetOwner", "icacls"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("the elevated script uses %q:\n%s", forbidden, script)
		}
	}
	if strings.Count(script, "Out-File") != 1 || !strings.Contains(script, "Out-File -LiteralPath $log -Append") {
		t.Fatalf("the elevated script must only append to the pairing's log:\n%s", script)
	}
}

func TestWindowsServiceLogExplainsTheFolderOwner(t *testing.T) {
	dir := t.TempDir()
	// No log yet: an unknown worker failure keeps the generic sentence.
	if hint := serviceNotReadyHint(dir); hint != nil {
		t.Fatalf("a missing log named %v", hint)
	}
	recordServiceLog(dir, "unsafe_state_directory")
	// The log alone is not enough: this folder is owned by the test account, so
	// the Hook folder is not the cause.
	if hint := serviceNotReadyHint(dir); hint != nil {
		t.Fatalf("a user-owned folder named %v", hint)
	}
	previous := windowsServiceFolderOwner
	windowsServiceFolderOwner = func(string) bool { return true }
	defer func() { windowsServiceFolderOwner = previous }()
	if hint := serviceNotReadyHint(dir); !errors.Is(hint, errServiceFolderOwner) {
		t.Fatalf("hint = %v, want errServiceFolderOwner", hint)
	}
	// A different worker failure is mapped by nothing here.
	recordServiceLog(dir, "worker_restart_limit_reached")
	if hint := serviceNotReadyHint(dir); hint != nil {
		t.Fatalf("an unrelated log named %v", hint)
	}
	// The pairing line names the folder, one line, without a code or a path.
	line := sshPairServiceWarningLine(errServiceFolderOwner)
	if !strings.Contains(line, "owned by Administrators") {
		t.Fatalf("warning = %q", line)
	}
	if strings.Contains(line, "\n") || strings.Contains(line, "service_folder") || strings.Contains(line, `C:\`) {
		t.Fatalf("warning is not one support-safe line: %q", line)
	}
}

// The worker's output is kept as a bounded tail: a supervisor that runs for hours
// must not grow with its worker's logging.
func TestWindowsServiceLogKeepsOnlyTheTail(t *testing.T) {
	var tail tailBuffer
	tail.limit = 8
	for _, chunk := range []string{"0123456789", "abcdef"} {
		if _, err := tail.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
		if len(tail.buf) > tail.limit {
			t.Fatalf("tail grew to %d bytes", len(tail.buf))
		}
	}
	if string(tail.buf) != "89abcdef" {
		t.Fatalf("tail = %q", tail.buf)
	}
}
