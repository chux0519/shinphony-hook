//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func execAttach(name string, args []string) error {
	return execAttachEnv(name, args, os.Environ())
}
func execAttachEnv(name string, args, env []string) error {
	p, e := exec.LookPath(name)
	if e != nil {
		return e
	}
	return syscall.Exec(p, append([]string{p}, args...), env)
}
