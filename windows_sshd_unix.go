//go:build darwin || linux

package main

// `windows-sshd` only exists on Windows; the subcommand is still recognized so
// a copied command gives one clear answer instead of "unknown_command".

import (
	"errors"
	"io"
)

func windowsSSHDCLI(_ []string, _ io.Writer) error {
	return errors.New("windows_sshd_platform_not_supported")
}
