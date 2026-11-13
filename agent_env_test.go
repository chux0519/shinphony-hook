//go:build !windows

package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Codex hooks run with only the "core" environment; the terminal identity is
// read from the Codex process (2026-11-05: no task context since native hooks).
func TestAgentGetenvReadsTheAgentProcess(t *testing.T) {
	// Not /bin/sleep: macOS hides the environment of platform binaries (SIP);
	// Codex, like this test binary, is an ordinary user process.
	cmd := exec.Command(os.Args[0], "-test.run=^TestAgentEnvHelperProcess$")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "SHINPHONY_ENV_HELPER=1", "HC_TERMINAL_ID=t3", "HC_TERMINAL_SOCKET=/tmp/hc/default.sock", "TMUX_PANE=%2", "SECRET_TOKEN=nope"}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(300 * time.Millisecond)
	ctx := context.Background()
	empty := func(string) string { return "" }
	get := agentGetenv(ctx, cmd.Process.Pid, empty)
	if get("HC_TERMINAL_ID") != "t3" || get("HC_TERMINAL_SOCKET") != "/tmp/hc/default.sock" || get("TMUX_PANE") != "%2" {
		t.Fatalf("agent env not read: %q %q %q", get("HC_TERMINAL_ID"), get("HC_TERMINAL_SOCKET"), get("TMUX_PANE"))
	}
	if get("SECRET_TOKEN") != "" || len(processEnv(ctx, cmd.Process.Pid)) != 3 {
		t.Fatalf("only terminal keys may be read: %v", processEnv(ctx, cmd.Process.Pid))
	}
	own := func(k string) string {
		if k == "TMUX_PANE" {
			return "%9"
		}
		return ""
	}
	if agentGetenv(ctx, cmd.Process.Pid, own)("HC_TERMINAL_ID") != "" {
		t.Fatal("the hook's own terminal identity wins; no mixing with the agent's")
	}
	if len(processEnv(ctx, 1)) != 0 || len(processEnv(ctx, os.Getpid()+1_000_000)) != 0 {
		t.Fatal("init / missing process yields nothing")
	}
}

func TestAgentEnvHelperProcess(t *testing.T) {
	if os.Getenv("SHINPHONY_ENV_HELPER") != "1" {
		t.Skip("helper process only")
	}
	time.Sleep(5 * time.Second)
}
