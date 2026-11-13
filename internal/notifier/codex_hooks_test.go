package notifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Codex's hooks.json is shared with other tools (MemSpace installs there).
func TestCodexHooksInstall(t *testing.T) {
	home := fixtureStore(t).dir
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex"))
	os.Mkdir(filepath.Join(home, "codex"), 0700)
	m := Manager{Directory: filepath.Join(home, "creds")}
	hooksPath := filepath.Join(home, "codex", "hooks.json")
	theirs := `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"/usr/bin/memspace hook codex","timeout":5}]}]}}`
	os.WriteFile(hooksPath, []byte(theirs), 0600)
	exe := filepath.Join(home, "agent-1")
	for i := 0; i < 2; i++ {
		if err := m.Configure("codex", exe, true); err != nil {
			t.Fatal(i, err)
		}
	}
	raw, _ := os.ReadFile(hooksPath)
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct{ Command string }
		}
	}
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal(string(raw))
	}
	for _, event := range codexHooks.events {
		n := 0
		for _, g := range doc.Hooks[event] {
			for _, h := range g.Hooks {
				if strings.HasSuffix(h.Command, " codex-hook-all") && strings.Contains(h.Command, exe) {
					n++
				}
			}
		}
		if n != 1 {
			t.Fatal(event, n, string(raw))
		}
	}
	if !strings.Contains(string(raw), "memspace hook codex") {
		t.Fatal("other tool's hook lost")
	}
	if config, _ := os.ReadFile(filepath.Join(home, "codex", "config.toml")); !strings.Contains(string(config), "codex-notify-all") {
		t.Fatal("notify not installed")
	}
	// Upgrade to a new binary after another tool edited hooks.json.
	edited := strings.Replace(string(raw), "memspace hook codex", "memspace hook codex --v2", 1)
	os.WriteFile(hooksPath, []byte(edited), 0600)
	exe2 := filepath.Join(home, "shinphony-hook-2")
	if err := m.Configure("codex", exe2, true); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(hooksPath)
	if strings.Contains(string(raw), "agent-1") || strings.Count(string(raw), "shinphony-hook-2' codex-hook-all") != len(codexHooks.events) || !strings.Contains(string(raw), "--v2") {
		t.Fatal(string(raw))
	}
	if err := m.Uninstall("codex"); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(hooksPath)
	if strings.Contains(string(raw), "codex-hook-all") || !strings.Contains(string(raw), "memspace hook codex --v2") {
		t.Fatal(string(raw))
	}
	if _, err := os.Stat(filepath.Join(home, "codex", "config.toml")); !os.IsNotExist(err) {
		t.Fatal("config.toml created by install not removed")
	}
	// The old notify.py skill in hooks.json still blocks a second sender.
	os.WriteFile(hooksPath, []byte(`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"python3 scripts/notify.py codex-hook p"}]}]}}`), 0600)
	if err := m.Configure("codex", exe, true); err == nil || err.Error() != "existing_shinphony_config" {
		t.Fatal(err)
	}
}

func TestCodexLifecycleOnlyPreservesConfig(t *testing.T) {
	home := fixtureStore(t).dir
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, "codex")
	t.Setenv("CODEX_HOME", dir)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	config := []byte("# externally managed\nnotify = [\"/other/tool\"]\n")
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	hooksPath := filepath.Join(dir, "hooks.json")
	theirs := `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"/other/hook"}]}]}}`
	if err := os.WriteFile(hooksPath, []byte(theirs), 0600); err != nil {
		t.Fatal(err)
	}
	m := Manager{Directory: filepath.Join(home, "creds")}
	exe := filepath.Join(home, "shinphony-hook-test")
	if err := m.ConfigureCodexLifecycle(exe, false); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(hooksPath); string(raw) != theirs {
		t.Fatal("dry run wrote hooks")
	}
	for i := 0; i < 2; i++ {
		if err := m.ConfigureCodexLifecycle(exe, true); err != nil {
			t.Fatal(err)
		}
	}
	if raw, _ := os.ReadFile(path); string(raw) != string(config) {
		t.Fatal("config.toml changed")
	}
	raw, _ := os.ReadFile(hooksPath)
	if !strings.Contains(string(raw), "/other/hook") || strings.Count(string(raw), " codex-hook-all") != len(codexHooks.events) {
		t.Fatal("hooks lost or duplicated")
	}
	var installed struct {
		Hooks map[string][]struct {
			Matcher string            `json:"matcher"`
			Hooks   []json.RawMessage `json:"hooks"`
		} `json:"hooks"`
	}
	if json.Unmarshal(raw, &installed) != nil || len(installed.Hooks["PostToolUse"]) != 1 || installed.Hooks["PostToolUse"][0].Matcher != "Bash" {
		t.Fatal("missing narrow task-intent tool hook")
	}
	if _, err := os.Stat(filepath.Join(m.Directory, "codex-install.json")); !os.IsNotExist(err) {
		t.Fatal("notify journal changed")
	}
}

func TestParsePermissionRequest(t *testing.T) {
	for _, tc := range []struct{ raw, tool, command string }{
		{`{"hook_event_name":"PermissionRequest","session_id":"s","tool_name":"Bash","tool_input":{"command":"npm install ajv"}}`, "Bash", "npm install ajv"},
		{`{"hook_event_name":"PermissionRequest","session_id":"s","tool_name":"shell","tool_input":{"command":["git","push"]}}`, "shell", "git push"},
		{`{"hook_event_name":"PermissionRequest","session_id":"s","tool_name":"apply_patch","tool_input":{"path":"a.go"}}`, "apply_patch", `{"path":"a.go"}`},
	} {
		h, ok := ParseHook([]byte(tc.raw))
		if !ok || h.Tool != tc.tool || h.Command != tc.command {
			t.Fatal(tc.raw, h)
		}
	}
}
