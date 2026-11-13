//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

func detachUpdater(exe, dir, creds string) error {
	c := exec.Command(exe, "--state-dir", dir, "--credentials-dir", creds, "check-update")
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		return err
	}
	return c.Process.Release()
}
