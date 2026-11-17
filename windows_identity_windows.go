//go:build windows

package main

// Windows identity helpers for the SSH key installer and `windows-sshd`:
// whether this account is an administrator (UAC filters the Administrators
// group out of the token, so membership is read from the token's group list)
// and whether the process is elevated.

import (
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// windowsAdministratorsSID is BUILTIN\Administrators, S-1-5-32-544.
func windowsAdministratorsSID() (*windows.SID, error) {
	return windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
}

// windowsSystemSID is NT AUTHORITY\SYSTEM, S-1-5-18.
func windowsSystemSID() (*windows.SID, error) {
	return windows.CreateWellKnownSid(windows.WinLocalSystemSid)
}

// windowsIsElevated reports whether the token has administrator rights in this
// process, i.e. whether the user answered the UAC prompt for it.
func windowsIsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// windowsIsAdministrator reports whether the account is a member of
// Administrators, elevated or not. A non-elevated administrator runs with a
// filtered token in which the group is deny-only but still listed, and sshd
// still requires administrators_authorized_keys for that account.
func windowsIsAdministrator() bool {
	admin, err := windowsAdministratorsSID()
	if err != nil {
		return false
	}
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		return false
	}
	for _, group := range groups.AllGroups() {
		if group.Sid != nil && group.Sid.Equals(admin) {
			return true
		}
	}
	return false
}

// windowsKeyDirectory is this account's key directory and file name. The
// administrator branch never looks at home: an elevated step writes
// administrators_authorized_keys under ProgramData\ssh and nothing in the
// profile, which is the allowlist windowsElevatedWriteList pins for tests.
func windowsKeyDirectory(administrator bool, home string) (dir, file string) {
	if administrator {
		return sshdConfigDirectory(), "administrators_authorized_keys"
	}
	return filepath.Join(home, ".ssh"), "authorized_keys"
}

// windowsElevatedWriteList is every path an elevated Hook step may create or
// change: the shared administrator key file with its journal, lock and temp
// files in ProgramData\ssh, plus the request and log files the non-elevated
// pairing created before the prompt. Nothing under the user profile, and no
// other file anywhere.
func windowsElevatedWriteList(home, temp string) []string {
	dir, file := windowsKeyDirectory(true, home)
	return []string{
		filepath.Join(dir, file),
		filepath.Join(dir, ".shinphony-keys.json"),
		filepath.Join(dir, ".shinphony-keys.lock"),
		filepath.Join(dir, ".shinphony-key-<nonce>"),
		filepath.Join(temp, "request.json"),
		filepath.Join(temp, "elevated.log"),
	}
}

// windowsKeyDirectoryForAccount is where this account's key goes: the file sshd
// actually reads for it. An administrator's key goes to the shared file in
// ProgramData\ssh while sshd_config sends Administrators there (the default);
// otherwise, and for every other account, to its own .ssh directory (TF 162).
func windowsKeyDirectoryForAccount(home string) (dir, file string, admin bool) {
	return sshKeyTargetForAccount(windowsIsAdministrator(), windowsSSHDConfig(), home, sshdConfigDirectory())
}

// windowsSSHDConfig is sshd_config's content, or nil when it cannot be read
// (then an administrator keeps the shared key file).
func windowsSSHDConfig() []byte {
	file, err := os.Open(filepath.Join(sshdConfigDirectory(), "sshd_config"))
	if err != nil {
		return nil
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return nil
	}
	if data == nil {
		data = []byte{}
	}
	return data
}

// describeKeyTarget is the file this account's key is installed into. It is
// reported by `windows-sshd status` and used by the key installer.
func describeKeyTarget(home string) string {
	dir, file, _ := windowsKeyDirectoryForAccount(home)
	return filepath.Join(dir, file)
}

// sshdConfigDirectory is sshd's program-data directory on Windows.
func sshdConfigDirectory() string {
	if dir := os.Getenv("ProgramData"); dir != "" {
		return filepath.Join(dir, "ssh")
	}
	return filepath.Join(`C:\ProgramData`, "ssh")
}
