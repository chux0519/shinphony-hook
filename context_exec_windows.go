package main

import (
	"os"
	"os/exec"
)

func execAttach(name string, args []string) error { return execAttachEnv(name, args, os.Environ()) }
func execAttachEnv(name string, args, env []string) error {
	cmd := exec.Command(name, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
