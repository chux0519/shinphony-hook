package main

// TF 161: on Windows the pairing filled the App's user as
// `DESKTOP-0SPR7A5\chuxd`. Reached through a jump host, the App runs `ssh` on
// the jump's POSIX shell, where the unquoted backslash is eaten, so the login
// never matched. A local account is reported as its plain name; a real domain
// account keeps its domain.

import "testing"

func TestSSHPairPlainUserName(t *testing.T) {
	cases := []struct {
		name     string
		username string
		machines []string
		want     string
	}{
		{"local account, machine name", `DESKTOP-0SPR7A5\chuxd`, []string{"DESKTOP-0SPR7A5"}, "chuxd"},
		{"local account, case-insensitive", `desktop-0spr7a5\chuxd`, []string{"DESKTOP-0SPR7A5"}, "chuxd"},
		{"local account, COMPUTERNAME as the other candidate", `DESKTOP-0SPR7A5\chuxd`, []string{"other-pc", "DESKTOP-0SPR7A5"}, "chuxd"},
		{"domain account keeps its domain", `HOMELAB\chuxd`, []string{"DESKTOP-0SPR7A5"}, `HOMELAB\chuxd`},
		{"Microsoft account keeps its domain", `MicrosoftAccount\chuxd@example.com`, []string{"DESKTOP-0SPR7A5"}, `MicrosoftAccount\chuxd@example.com`},
		{"plain name is unchanged", "chuxd", []string{"DESKTOP-0SPR7A5"}, "chuxd"},
		{"empty name is unchanged", "", []string{"DESKTOP-0SPR7A5"}, ""},
		{"no machine candidate", `DESKTOP-0SPR7A5\chuxd`, nil, `DESKTOP-0SPR7A5\chuxd`},
		{"empty machine candidate", `DESKTOP-0SPR7A5\chuxd`, []string{""}, `DESKTOP-0SPR7A5\chuxd`},
		{"only strips a real domain part", `\chuxd`, []string{"DESKTOP-0SPR7A5"}, `\chuxd`},
		{"only strips a real user part", `DESKTOP-0SPR7A5\`, []string{"DESKTOP-0SPR7A5"}, `DESKTOP-0SPR7A5\`},
		{"keeps a backslash that is not a domain split", `DESKTOP-0SPR7A5\sub\chuxd`, []string{"DESKTOP-0SPR7A5"}, `DESKTOP-0SPR7A5\sub\chuxd`},
		{"trims surrounding machine whitespace", `DESKTOP-0SPR7A5\chuxd`, []string{" DESKTOP-0SPR7A5 "}, "chuxd"},
	}
	for _, c := range cases {
		if got := sshPairPlainUserName(c.username, c.machines...); got != c.want {
			t.Errorf("%s: sshPairPlainUserName(%q, %q) = %q, want %q", c.name, c.username, c.machines, got, c.want)
		}
	}
}
