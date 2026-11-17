//go:build darwin || linux

package main

// The Unix side of `pair`: /dev/tty for the prompts and the QR, ssh-keyscan for
// the local host keys, and the "never root" rule. The flow itself is in
// ssh_pair_cli.go.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

func sshPairPrivilegeCheck() error {
	if os.Geteuid() == 0 {
		return errors.New("keys_root_not_supported")
	}
	return nil
}

// openSSHPairConsole opens the controlling terminal; stdin and stdout may be
// redirected (the one-line installer pipes the script), so both the prompts and
// the QR go to /dev/tty.
func openSSHPairConsole() (*sshPairConsole, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &sshPairConsole{
		input:  bufio.NewReader(tty),
		output: tty,
		close:  func() { tty.Close() },
	}, nil
}

// installSSHPairKey installs the key the phone approved. Unix never needs
// elevation for this, so the shared installer is the whole implementation.
func installSSHPairKey(home string, request sshKeyRequest) error {
	_, err := manageSSHKey(home, "install", request)
	return err
}

func localSSHPins(port int) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/ssh-keyscan", "-T", "3", "-p", fmt.Sprint(port), "-t", "ed25519,ecdsa,rsa", "127.0.0.1").Output()
	if err != nil || len(output) > 16384 {
		return nil, errors.New("ssh_pair_local_ssh_unavailable")
	}
	return sshPinsFromKeyscanOutput(output)
}

// sshPairReportedUserName is the account name as it is: only Windows prefixes it.
func sshPairReportedUserName(username string) string { return username }
