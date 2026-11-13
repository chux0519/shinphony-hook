package main

import (
	"errors"
	"strings"
	"testing"
)

func TestCodexDiagnosticsReadOnly(t *testing.T) {
	for _, tc := range []struct{ name, features, version, want string }{
		{"running", "daemon_auto_start stable true", `{"status":"running","socketPath":"SECRET"}`, "codex_shared_backend_running"},
		{"disabled_but_running", "daemon_auto_start stable false", `{"status":"running"}`, "codex_shared_backend_running"},
		{"enabled", "daemon_auto_start stable true", `{}`, "codex_shared_backend_enabled"},
		{"unknown", "", "", "codex_backend_unknown"},
		{"disabled_not_proven", "daemon_auto_start stable false", `{"status":"new_schema"}`, "codex_backend_unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			d := probeCodex(func(args ...string) ([]byte, error) {
				calls++
				switch strings.Join(args, " ") {
				case "features list":
					return []byte(tc.features), nil
				case "app-server daemon version":
					return []byte(tc.version), nil
				default:
					t.Fatal("mutating or unexpected command", args)
					return nil, nil
				}
			})
			if d.Code != tc.want || calls != 2 {
				t.Fatalf("%+v calls=%d", d, calls)
			}
		})
	}
	d := probeCodex(func(...string) ([]byte, error) { return nil, errors.New("missing binary") })
	if d.Code != "codex_backend_unknown" {
		t.Fatal(d)
	}
}

func TestDiagnosticOutputBound(t *testing.T) {
	b := &diagnosticOutput{}
	if _, err := b.Write(make([]byte, 65537)); err == nil || len(b.data) != 0 {
		t.Fatal("unbounded output")
	}
}
