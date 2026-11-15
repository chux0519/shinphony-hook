package notifier

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A09: the generated document must load the way Antigravity's own loader reads
// it. `agy plugin validate` runs the plugin hooks loader without a model call
// or credentials, so this proves schema/load compatibility only - not that the
// agent fires the hooks at the documented moments at runtime.
func TestAgyHooksLoadInLocalAgy(t *testing.T) {
	agy, err := exec.LookPath("agy")
	if err != nil {
		t.Skip("agy CLI not installed")
	}
	s := fixtureStore(t)
	exe := filepath.Join(s.dir, "bin with spaces", "agent-1")
	hooks, err := proposedAgy(nil, exe)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plugin.json"), []byte(`{"name":"shinphony-hooks-check","version":"1.0.0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hooks.json"), hooks, 0600); err != nil {
		t.Fatal(err)
	}
	validate := func(dir string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, agy, "plugin", "validate", dir, "--strict", "--json")
		out, err := cmd.Output()
		return string(out), err
	}
	out, err := validate(dir)
	if err != nil {
		t.Fatalf("agy plugin validate rejected the generated hooks: %v\n%s", err, out)
	}
	var report struct {
		Components struct {
			Hooks int `json:"hooks"`
		} `json:"components"`
		Findings []struct {
			Severity string `json:"severity"`
			Message  string `json:"message"`
		} `json:"findings"`
	}
	if json.Unmarshal([]byte(out), &report) != nil || report.Components.Hooks != 1 {
		t.Fatal(out)
	}
	for _, finding := range report.Findings {
		// A note is how the loader reports what it did (for example the missing
		// plugin logo). Anything else means a hook would be skipped or ignored.
		if finding.Severity != "note" {
			t.Fatalf("%s: %s\n%s", finding.Severity, finding.Message, out)
		}
	}

	// The same command rejects the matcher-wrapped shape the official docs
	// forbid for SessionStart, so the check above is not vacuous.
	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, "plugin.json"), []byte(`{"name":"shinphony-bad-shape","version":"1.0.0"}`), 0600)
	os.WriteFile(filepath.Join(bad, "hooks.json"), []byte(`{"g":{"SessionStart":[{"hooks":[{"type":"command","command":"/bin/true"}]}]}}`), 0600)
	if out, err = validate(bad); err == nil || !strings.Contains(out, "must specify 'command'") {
		t.Fatalf("validator accepted the wrong event shape: %v\n%s", err, out)
	}
}