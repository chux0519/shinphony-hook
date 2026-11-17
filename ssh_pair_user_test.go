package main

// TF 161: on Windows the pairing filled the App's user as
// `DESKTOP-EXAMPLE1\alex`. Reached through a jump host, the App runs `ssh` on
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
		{"local account, machine name", `DESKTOP-EXAMPLE1\alex`, []string{"DESKTOP-EXAMPLE1"}, "alex"},
		{"local account, case-insensitive", `desktop-example1\alex`, []string{"DESKTOP-EXAMPLE1"}, "alex"},
		{"local account, COMPUTERNAME as the other candidate", `DESKTOP-EXAMPLE1\alex`, []string{"other-pc", "DESKTOP-EXAMPLE1"}, "alex"},
		{"domain account keeps its domain", `EXAMPLEDOM\alex`, []string{"DESKTOP-EXAMPLE1"}, `EXAMPLEDOM\alex`},
		{"Microsoft account keeps its domain", `MicrosoftAccount\alex`, []string{"DESKTOP-EXAMPLE1"}, `MicrosoftAccount\alex`},
		{"plain name is unchanged", "alex", []string{"DESKTOP-EXAMPLE1"}, "alex"},
		{"empty name is unchanged", "", []string{"DESKTOP-EXAMPLE1"}, ""},
		{"no machine candidate", `DESKTOP-EXAMPLE1\alex`, nil, `DESKTOP-EXAMPLE1\alex`},
		{"empty machine candidate", `DESKTOP-EXAMPLE1\alex`, []string{""}, `DESKTOP-EXAMPLE1\alex`},
		{"only strips a real domain part", `\alex`, []string{"DESKTOP-EXAMPLE1"}, `\alex`},
		{"only strips a real user part", `DESKTOP-EXAMPLE1\`, []string{"DESKTOP-EXAMPLE1"}, `DESKTOP-EXAMPLE1\`},
		{"keeps a backslash that is not a domain split", `DESKTOP-EXAMPLE1\sub\alex`, []string{"DESKTOP-EXAMPLE1"}, `DESKTOP-EXAMPLE1\sub\alex`},
		{"trims surrounding machine whitespace", `DESKTOP-EXAMPLE1\alex`, []string{" DESKTOP-EXAMPLE1 "}, "alex"},
	}
	for _, c := range cases {
		if got := sshPairPlainUserName(c.username, c.machines...); got != c.want {
			t.Errorf("%s: sshPairPlainUserName(%q, %q) = %q, want %q", c.name, c.username, c.machines, got, c.want)
		}
	}
}
