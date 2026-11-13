package main

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// Diagnostics never start/stop a server or change Codex configuration. A shared
// server is a host-level risk, not proof that a particular thread uses it.
type codexDiagnostics struct {
	Schema    int    `json:"schema"`
	AutoStart string `json:"autoStart"`
	Server    string `json:"server"`
	Code      string `json:"code"`
}

type diagnosticOutput struct{ data []byte }

func (b *diagnosticOutput) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 65536 {
		return 0, errors.New("output_limit")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func diagnoseCodex() codexDiagnostics {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return probeCodex(func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "codex", args...)
		cmd.WaitDelay = 100 * time.Millisecond
		out := &diagnosticOutput{}
		cmd.Stdout = out
		err := cmd.Run()
		return out.data, err
	})
}

func probeCodex(run func(...string) ([]byte, error)) codexDiagnostics {
	d := codexDiagnostics{Schema: 1, AutoStart: "unknown", Server: "unknown", Code: "codex_backend_unknown"}
	if raw, err := run("features", "list"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) == 3 && f[0] == "daemon_auto_start" {
				if f[2] == "true" {
					d.AutoStart = "enabled"
				} else if f[2] == "false" {
					d.AutoStart = "disabled"
				}
			}
		}
	}
	if raw, err := run("app-server", "daemon", "version"); err == nil {
		var result struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(raw, &result) == nil && result.Status == "running" {
			d.Server = "running"
		}
		// Unknown/unsupported responses and failed connections are not evidence
		// that no shared server exists. Keep them explicitly unknown.
	}
	if d.Server == "running" {
		d.Code = "codex_shared_backend_running"
	} else if d.AutoStart == "enabled" {
		d.Code = "codex_shared_backend_enabled"
	}
	return d
}
