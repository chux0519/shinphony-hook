//go:build windows

package main

// Installing an administrator's key needs one more UAC prompt: the key file is
// C:\ProgramData\ssh\administrators_authorized_keys, which a non-elevated
// administrator token cannot write. The pairing itself keeps running in the
// user's own window - that is where the prompts and the QR belong, and where
// every state file stays owned by the user - so this file is only the short,
// fixed elevated step that runs `keys install`.
//
// Nothing created by that step lives under the user profile: the request file
// and the log are created here, by the non-elevated pairing, and the elevated
// process only reads the first and appends to the second.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

const (
	// sshPairElevatedTimeout waits for the user to answer the prompt and for the
	// key write, so it is generous but finite.
	sshPairElevatedTimeout = 10 * time.Minute
	sshPairElevatedRefused = "Administrator permission was not given, so the key was not installed. Run pair again and approve the prompt."
	sshPairElevatedFailed  = "The administrator step could not install the key. Run pair again from a normal PowerShell window."
)

// installSSHPairKey installs the key the phone approved: in this process when it
// may, and in one short elevated process when the account is an administrator.
func installSSHPairKey(home string, request sshKeyRequest) error {
	_, err := manageSSHKey(home, "install", request)
	if err == nil || !errors.Is(err, errSSHPairNeedsAdmin) {
		return err
	}
	// A pairing that already runs elevated (the user started it from an
	// administrator window) has the right to write the file; pass the refusal
	// through unchanged instead of elevating twice.
	if windowsIsElevated() {
		return err
	}
	return installSSHPairKeyElevated(request)
}

// installSSHPairKeyElevated writes the approved request into a private temp
// directory, then asks for one more UAC prompt. The elevated script reads that
// file and pipes it into `keys install`, which validates it again - the strict
// JSON shape, the key id pattern and the P-256 public key - before writing
// anything. No request text is interpolated into a command line: the script
// travels as -EncodedCommand and every path in it is single quoted.
func installSSHPairKeyElevated(request sshKeyRequest) error {
	executable, err := os.Executable()
	if err != nil {
		return errors.New(sshPairElevatedFailed)
	}
	dir, err := newPrivateTempDir("shinphony-key-")
	if err != nil {
		return errors.New(sshPairElevatedFailed)
	}
	defer os.RemoveAll(dir)
	raw, err := json.Marshal(request)
	if err != nil {
		return errors.New(sshPairElevatedFailed)
	}
	requestPath := filepath.Join(dir, "request.json")
	if err = os.WriteFile(requestPath, raw, 0600); err != nil {
		return errors.New(sshPairElevatedFailed)
	}
	// The log is created here, not by the elevated process, so it stays owned by
	// the user and no file is created under the profile with an elevated owner.
	logPath := filepath.Join(dir, "elevated.log")
	if err = os.WriteFile(logPath, nil, 0600); err != nil {
		return errors.New(sshPairElevatedFailed)
	}
	sid, err := currentSID()
	if err != nil {
		return errors.New(sshPairElevatedFailed)
	}
	inner := windowsElevatedKeyInstallScript(executable, requestPath, logPath, sid.String())
	// The prompt appears while the QR is on screen: say why it is there.
	fmt.Fprintln(os.Stderr, "Shinphony needs administrator permission to add this key for an administrator account.")
	ctx, cancel := context.WithTimeout(context.Background(), sshPairElevatedTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsElevatedShellCommand(inner))
	runErr := command.Run()
	report := readElevatedReport(logPath)
	if runErr != nil {
		// An empty log means the elevated window never started: the prompt was
		// declined, which is a different sentence from a failed install.
		if report != "" {
			fmt.Fprint(os.Stderr, report)
			return errors.New(sshPairElevatedFailed)
		}
		return errors.New(sshPairElevatedRefused)
	}
	return nil
}

// newPrivateTempDir creates a directory in the user's temp directory with the
// same ACL as the agent's state directory (this account only), so the request
// file inside it inherits that ACL.
func newPrivateTempDir(prefix string) (string, error) {
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	dir := filepath.Join(os.TempDir(), prefix+hex.EncodeToString(nonce))
	sa, err := attributes()
	if err != nil {
		return "", err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", err
	}
	if err = windows.CreateDirectory(p, sa); err != nil {
		return "", err
	}
	return dir, nil
}

// windowsElevatedKeyInstallScript is the whole elevated step. It checks that the
// prompt was answered by this same account, reads the request, and leaves the
// validation and the write to `keys install`. A failure stays visible in that
// window and in the log the normal window prints.
func windowsElevatedKeyInstallScript(executable, requestPath, logPath, sid string) string {
	return `$ErrorActionPreference = 'Stop'
$log = ` + psLiteral(logPath) + `
try {
  if ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne ` + psLiteral(sid) + `) {
    throw 'Administrator permission was given to a different account, so the key was not installed.'
  }
  $request = [System.IO.File]::ReadAllText(` + psLiteral(requestPath) + `)
  if ($request.Length -lt 1 -or $request.Length -gt 8192) { throw 'The key request is not valid.' }
  $request | & ` + psLiteral(executable) + ` keys install *>> $log
  $code = $LASTEXITCODE
} catch {
  $_ | Out-File -LiteralPath $log -Append -Encoding UTF8
  $code = 1
}
if ($code -ne 0) {
  Write-Host 'The key for this administrator account was not installed.' -ForegroundColor Red
  Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | Write-Host
  Read-Host 'Press Enter to close this window.'
}
exit $code`
}

// windowsElevatedShellCommand is what the normal window runs: one Start-Process
// -Verb RunAs that waits, so pairing knows when the elevated step is done.
func windowsElevatedShellCommand(inner string) string {
	return `$p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -PassThru -Wait -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', ` +
		psLiteral(powershellArgument(inner)) + `)
exit $p.ExitCode`
}

// readElevatedReport is the tail of the log, which is all a failed step needs to
// explain itself; the start is the fixed script header.
func readElevatedReport(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	if len(data) > 4096 {
		data = data[len(data)-4096:]
	}
	return strings.TrimSpace(string(data))
}
