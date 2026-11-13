//go:build windows

package main

import (
	"errors"
	"io"
)

func sshPairSelected(args []string) bool {
	return len(args) > 1 && args[0] == "pair" && (args[1] == "--ssh" || args[1] == "--invitation-stdin")
}
func sshPairCLI(_ []string, _ io.Reader, _ io.Writer) error {
	return errors.New("keys_platform_not_supported")
}
