package main

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
)

// sshKeyTargetForAccount is the file sshd reads this account's keys from: an
// administrator's keys are in sshd's shared administrators_authorized_keys
// only while sshd_config sends members of Administrators there (Windows'
// default `Match Group administrators` block). Without that block sshd reads
// the account's own ~/.ssh/authorized_keys, and a key written to the shared file
// never signs in (TF 162). A nil config (unreadable) keeps the shared file for
// an administrator, the choice before sshd_config was consulted.
func sshKeyTargetForAccount(administrator bool, sshdConfig []byte, home, sshdDir string) (dir, file string, admin bool) {
	if administrator && (sshdConfig == nil || sshdReadsAdministratorsKeys(sshdConfig)) {
		return sshdDir, "administrators_authorized_keys", true
	}
	return filepath.Join(home, ".ssh"), "authorized_keys", false
}

// sshdReadsAdministratorsKeys reports whether, for a member of Administrators,
// the AuthorizedKeysFile sshd applies names administrators_authorized_keys. Like
// sshd, the first value obtained wins, and a value from a Match block that
// applies overrides the global one. A block applies when every criterion is
// `all` or a Group list naming administrators; any other criterion (User,
// Host, Address, a negation) is not certain to match, so it does not count.
func sshdReadsAdministratorsKeys(config []byte) bool {
	var global, matched string
	inMatch, applies := false, false
	scanner := bufio.NewScanner(bytes.NewReader(config))
	for scanner.Scan() {
		keyword, args := sshdConfigLine(scanner.Text())
		switch keyword {
		case "":
			continue
		case "match":
			inMatch = true
			applies = sshdMatchAppliesToAdministrators(args)
		case "authorizedkeysfile":
			value := strings.Join(args, " ")
			if !inMatch && global == "" {
				global = value
			}
			if inMatch && applies && matched == "" {
				matched = value
			}
		}
	}
	effective := global
	if matched != "" {
		effective = matched
	}
	return strings.Contains(strings.ToLower(effective), "administrators_authorized_keys")
}

// sshdConfigLine splits one sshd_config line into its lower-case keyword and
// arguments: `#` starts a comment, and `Keyword=value` equals `Keyword value`.
func sshdConfigLine(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '='
	})
	if len(fields) == 0 {
		return "", nil
	}
	return strings.ToLower(fields[0]), fields[1:]
}

func sshdMatchAppliesToAdministrators(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "all":
			continue
		case "group":
			if i+1 >= len(args) {
				return false
			}
			i++
			named := false
			for _, group := range strings.Split(args[i], ",") {
				if strings.EqualFold(strings.Trim(group, `"`), "administrators") {
					named = true
				}
			}
			if !named {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// sshKeyFileSDDL is the creation ACL for the key directory, the key file and
// its temp/lock files. The shared administrator file is Administrators and
// SYSTEM only, as sshd demands. A user's file keeps what a profile gives it:
// the user, SYSTEM and Administrators. sshd opens authorized_keys as SYSTEM, so
// a user-only file is "Could not open authorized keys: Permission denied" for
// every key in it (the replace carries this ACL to the whole file).
func sshKeyFileSDDL(admin bool, userSID string) string {
	if admin {
		return "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"
	}
	return "O:" + userSID + "D:P(A;OICI;FA;;;" + userSID + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
}
