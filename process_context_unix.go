//go:build !windows

package main

import (
	"context"
	"os"
	"strconv"
	"strings"
)

func processStart(ctx context.Context, pid int) string {
	if pid <= 1 {
		return ""
	}
	s, e := commandOutput(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "lstart=")
	if e != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

func processParent(ctx context.Context, pid int) int {
	raw, e := commandOutput(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "ppid=")
	if e != nil {
		return 0
	}
	value, _ := strconv.Atoi(strings.TrimSpace(raw))
	return value
}
func processName(ctx context.Context, pid int) string {
	raw, e := commandOutput(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	if e != nil {
		return ""
	}
	return strings.TrimSpace(raw)
}

// terminalEnvKeys locate an agent's terminal. Codex starts hook processes
// with an empty environment and replays only what shell_environment_policy
// allows ("core" drops them), so the hook reads them from the agent itself.
var terminalEnvKeys = map[string]bool{"HC_TERMINAL_ID": true, "HC_TERMINAL_SOCKET": true, "HC_SESSION": true,
	"TMUX": true, "TMUX_PANE": true, "CODEX_HOME": true}

// processEnv returns terminalEnvKeys from a process the user owns: Linux
// /proc/<pid>/environ (exact); macOS `ps eww` (space-separated, so a value
// containing a space is skipped).
func processEnv(ctx context.Context, pid int) map[string]string {
	out := map[string]string{}
	if pid <= 1 {
		return out
	}
	var fields []string
	if raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ"); err == nil {
		fields = strings.Split(string(raw), "\x00")
	} else if raw, err := commandOutput(ctx, "ps", "eww", "-o", "command=", "-p", strconv.Itoa(pid)); err == nil {
		fields = strings.Fields(raw)
	}
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if ok && terminalEnvKeys[k] && v != "" && len(v) <= 1024 {
			out[k] = v
		}
	}
	return out
}
