package main

import "strings"

// sshPairPlainUserName is the user name the pairing reports to the App. On
// Windows Go reports a local account as `COMPUTER\user`; reached through a jump
// host, the App runs `ssh` on the jump's POSIX shell, where that backslash is
// eaten (TF 161). A local account is therefore reported as its plain name: the
// domain part equals one of this computer's names (case-insensitive). A real
// domain or Microsoft account keeps its `DOMAIN\user` form.
func sshPairPlainUserName(username string, machines ...string) string {
	domain, name, ok := strings.Cut(username, `\`)
	if !ok || domain == "" || name == "" || strings.Contains(name, `\`) {
		return username
	}
	for _, machine := range machines {
		if machine = strings.TrimSpace(machine); machine != "" && strings.EqualFold(domain, machine) {
			return name
		}
	}
	return username
}
