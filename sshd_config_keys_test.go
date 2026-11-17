package main

import (
	"path/filepath"
	"testing"
)

// Windows' default sshd_config, abridged to the lines that matter.
const defaultWindowsSSHDConfig = "# This is the sshd server system-wide configuration file.\r\n" +
	"#PubkeyAuthentication yes\r\n" +
	"AuthorizedKeysFile\t.ssh/authorized_keys\r\n" +
	"Subsystem\tsftp\tsftp-server.exe\r\n" +
	"\r\n" +
	"Match Group administrators\r\n" +
	"       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\r\n"

// sshd reads an administrator's keys from administrators_authorized_keys only
// while sshd_config says so; a computer where that block is commented out (or
// gone) reads ~/.ssh/authorized_keys, and a key written to the shared file
// never signs in (TF 162: "Target server authentication failed" after a
// successful pairing).
func TestSSHKeyTargetFollowsSSHDConfig(t *testing.T) {
	home := filepath.Join("C:", "Users", "alex")
	sshdDir := filepath.Join("C:", "ProgramData", "ssh")
	user := [2]string{filepath.Join(home, ".ssh"), "authorized_keys"}
	shared := [2]string{sshdDir, "administrators_authorized_keys"}
	commented := "AuthorizedKeysFile .ssh/authorized_keys\r\n" +
		"#Match Group administrators\r\n" +
		"#       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\r\n"
	cases := []struct {
		name          string
		administrator bool
		config        string
		want          [2]string
		wantAdmin     bool
	}{
		{"default config, administrator", true, defaultWindowsSSHDConfig, shared, true},
		{"default config, standard user", false, defaultWindowsSSHDConfig, user, false},
		{"block commented out", true, commented, user, false},
		{"block removed", true, "AuthorizedKeysFile .ssh/authorized_keys\n", user, false},
		{"empty config", true, "", user, false},
		{"keyword and group case, quoted group", true, "match group \"Administrators\"\n  authorizedkeysfile __PROGRAMDATA__/ssh/administrators_authorized_keys\n", shared, true},
		{"group in a list", true, "Match Group sshusers,administrators\nAuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n", shared, true},
		{"other group only", true, "Match Group sshusers\nAuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n", user, false},
		{"block without AuthorizedKeysFile", true, "Match Group administrators\n  PasswordAuthentication no\n", user, false},
		{"a later Match ends the block", true, "Match Group administrators\nMatch User alex\nAuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n", user, false},
		{"Match all", true, "Match all\nAuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n", shared, true},
		{"global points at the shared file", true, "AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n", shared, true},
		{"equals sign form", true, "Match Group=administrators\nAuthorizedKeysFile=__PROGRAMDATA__/ssh/administrators_authorized_keys\n", shared, true},
	}
	for _, c := range cases {
		dir, file, admin := sshKeyTargetForAccount(c.administrator, []byte(c.config), home, sshdDir)
		if [2]string{dir, file} != c.want || admin != c.wantAdmin {
			t.Errorf("%s: got %s/%s admin=%v, want %s/%s admin=%v", c.name, dir, file, admin, c.want[0], c.want[1], c.wantAdmin)
		}
	}
	// No readable sshd_config: keep the shared file, today's choice.
	if dir, file, admin := sshKeyTargetForAccount(true, nil, home, sshdDir); [2]string{dir, file} != shared || !admin {
		t.Errorf("unreadable config: got %s/%s admin=%v, want the shared file", dir, file, admin)
	}
}

// sshd opens authorized_keys as SYSTEM: a user's key file that only the user
// may read is "Could not open authorized keys ... Permission denied", and
// because the file is replaced, pairing would also lock out every key that was
// already there. The user's file keeps the profile's usual entries: the user,
// SYSTEM and Administrators (the owners sshd accepts), nobody else.
func TestSSHKeyFileSDDL(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	if got, want := sshKeyFileSDDL(false, user), "O:"+user+"D:P(A;OICI;FA;;;"+user+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"; got != want {
		t.Errorf("user key file SDDL = %q, want %q", got, want)
	}
	if got, want := sshKeyFileSDDL(true, user), "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"; got != want {
		t.Errorf("administrator key file SDDL = %q, want %q", got, want)
	}
}
