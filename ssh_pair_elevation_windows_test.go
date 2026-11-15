//go:build windows

package main

// The second, short elevated step that installs an administrator's key. It is
// built as text, so its shape is pinned here: what it runs, that every path is
// single quoted, that it checks the account, and that the inner script really
// travels as -EncodedCommand.

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"unicode/utf16"
)

// decodeEncodedCommand is the inverse of powershellArgument, so the test reads
// exactly what PowerShell would receive.
func decodeEncodedCommand(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("encoded command is not base64 UTF-16LE: %v", err)
	}
	words := make([]uint16, len(raw)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	return string(utf16.Decode(words))
}

func TestWindowsElevatedKeyInstallScriptIsFixed(t *testing.T) {
	script := windowsElevatedKeyInstallScript(
		`C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe`,
		`C:\Users\you\AppData\Local\Temp\shinphony-key-1\request.json`,
		`C:\Users\you\AppData\Local\Temp\shinphony-key-1\elevated.log`,
		"S-1-5-21-1-2-3-1001")
	for _, want := range []string{
		"keys install",
		"$ErrorActionPreference = 'Stop'",
		"$LASTEXITCODE",
		"Read-Host 'Press Enter to close this window.'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("the elevated script is missing %q:\n%s", want, script)
		}
	}
	// The request is read from the file the pairing wrote; no key text is ever
	// interpolated into the script.
	if strings.Contains(script, "ecdsa-sha2-nistp256") {
		t.Fatal("the elevated script must not embed key material")
	}
	// Nothing in the elevated step sets an owner or a whole descriptor: the only
	// ACL work is done by the hook itself, on ProgramData\ssh.
	if strings.Contains(script, "Set-Acl") || strings.Contains(script, "SetOwner") {
		t.Fatal("the elevated script must not touch an owner")
	}
	// The account that answered the prompt must be the one that asked for it.
	if !strings.Contains(script, "S-1-5-21-1-2-3-1001") {
		t.Fatal("the elevated script must check the account")
	}
}

func TestWindowsElevatedKeyInstallScriptQuotesPaths(t *testing.T) {
	script := windowsElevatedKeyInstallScript(`C:\it's\hook.exe`, `C:\it's\request.json`, `C:\it's\log`, "S-1-5-21-1")
	// PowerShell single quotes double an embedded one; a path with an apostrophe
	// must not end the literal.
	if strings.Contains(script, `\it's\`) {
		t.Fatalf("a single quote in a path was not doubled:\n%s", script)
	}
	if !strings.Contains(script, `\it''s\`) {
		t.Fatalf("a single quote in a path was not doubled:\n%s", script)
	}
}

func TestWindowsElevatedShellCommandPassesTheInnerScriptEncoded(t *testing.T) {
	inner := windowsElevatedKeyInstallScript(`C:\hook.exe`, `C:\request.json`, `C:\log`, "S-1-5-21-1")
	outer := windowsElevatedShellCommand(inner)
	for _, want := range []string{"-Verb RunAs", "-Wait", "-PassThru", "exit $p.ExitCode"} {
		if !strings.Contains(outer, want) {
			t.Fatalf("the outer command is missing %q:\n%s", want, outer)
		}
	}
	const marker = "'-EncodedCommand', '"
	start := strings.Index(outer, marker)
	if start < 0 {
		t.Fatalf("the outer command does not pass -EncodedCommand:\n%s", outer)
	}
	encoded := outer[start+len(marker):]
	end := strings.Index(encoded, "'")
	if end < 0 {
		t.Fatalf("the encoded command is not single quoted:\n%s", outer)
	}
	encoded = encoded[:end]
	if encoded != powershellArgument(inner) {
		t.Fatal("the outer command does not carry powershellArgument(inner)")
	}
	if got := decodeEncodedCommand(t, encoded); !strings.Contains(got, "keys install") {
		t.Fatalf("the encoded command does not decode to the inner script: %q", got)
	}
	// No part of the inner script may reach the outer command as plain text: a
	// shell could split it.
	if strings.Contains(outer, "keys install") {
		t.Fatal("the inner script was interpolated as text")
	}
}

// The log the normal window prints is created before elevation, so the elevated
// process only appends to a file the user owns.
func TestWindowsElevatedReportIsTheLogTail(t *testing.T) {
	path := t.TempDir() + `\elevated.log`
	if report := readElevatedReport(path); report != "" {
		t.Fatalf("a missing log reported %q", report)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if report := readElevatedReport(path); report != "" {
		t.Fatalf("an empty log reported %q", report)
	}
	if err := os.WriteFile(path, []byte("ssh_pair_needs_admin\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if report := readElevatedReport(path); report != "ssh_pair_needs_admin" {
		t.Fatalf("report = %q", report)
	}
}
