//go:build darwin || linux

package main

// The Unix side of `pair`: /dev/tty for the prompts and the QR, ssh-keyscan for
// the local host keys, and the "never root" rule. The flow itself is in
// ssh_pair_cli.go.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
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

func localSSHPins(port int) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/ssh-keyscan", "-T", "3", "-p", fmt.Sprint(port), "-t", "ed25519,ecdsa,rsa", "127.0.0.1").Output()
	if err != nil || len(output) > 16384 {
		return nil, errors.New("ssh_pair_local_ssh_unavailable")
	}
	pins := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		blob, err := base64.StdEncoding.Strict().DecodeString(fields[2])
		if err != nil || len(blob) > 8192 {
			continue
		}
		hash := sha256.Sum256(blob)
		pin := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
		if !seen[pin] {
			pins = append(pins, pin)
			seen[pin] = true
		}
	}
	if len(pins) == 0 || len(pins) > 4 {
		return nil, errors.New("ssh_pair_local_ssh_unavailable")
	}
	return pins, nil
}
