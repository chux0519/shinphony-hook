//go:build windows

package main

// Windows identity helpers for the SSH key installer and `windows-sshd`:
// whether this account is an administrator (UAC filters the Administrators
// group out of the token, so membership is read from the token's group list)
// and whether the process is elevated.

import (
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

// windowsKeyDirectoryForAccount is where this account's key goes: the
// Administrators file lives in ProgramData\ssh, every other account in its own
// .ssh directory.
func windowsKeyDirectoryForAccount(home string) (dir, file string, admin bool) {
	if windowsIsAdministrator() {
		return sshdConfigDirectory(), "administrators_authorized_keys", true
	}
	return filepath.Join(home, ".ssh"), "authorized_keys", false
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
