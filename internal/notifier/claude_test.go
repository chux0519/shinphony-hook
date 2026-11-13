package notifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeInstallRoundTrip(t *testing.T) {
	s := fixtureStore(t)
	p := filepath.Join(s.dir, "settings.json")
	exe := filepath.Join(s.dir, "a b", "notify")
	original := []byte(`{"custom":9007199254740993,"hooks":{"Stop":[{"hooks":[{"type":"command","command":"other"}]}]}}`)
	os.WriteFile(p, original, 0600)
	for i := 0; i < 2; i++ {
		if e := s.configureAgent("claude", p, exe, true, proposedClaude); e != nil {
			t.Fatal(e)
		}
	}
	raw, _ := os.ReadFile(p)
	var doc map[string]json.RawMessage
	json.Unmarshal(raw, &doc)
	if string(doc["custom"]) != "9007199254740993" {
		t.Fatal("changed unknown number")
	}
	var hooks map[string][]json.RawMessage
	json.Unmarshal(doc["hooks"], &hooks)
	if len(hooks["Stop"]) != 2 || len(hooks["Notification"]) != 1 {
		t.Fatal("lost hooks or duplicated install")
	}
	if e := s.uninstallAgent("claude"); e != nil {
		t.Fatal(e)
	}
	raw, _ = os.ReadFile(p)
	if string(raw) != string(original) {
		t.Fatal("not exact restore")
	}
}
func TestClaudeEvents(t *testing.T) {
	for _, tc := range []struct{ raw, status string }{
		{`{"hook_event_name":"Stop","session_id":"s"}`, ""},
		{`{"hook_event_name":"Notification","session_id":"s","notification_type":"permission_prompt"}`, "attention"},
		{`{"hook_event_name":"Stop","session_id":"s","stop_hook_active":true}`, ""},
		{`{"hook_event_name":"SubagentStop","session_id":"s"}`, ""},
		{`{"hook_event_name":"Notification","session_id":"s","notification_type":"idle_prompt"}`, ""},
	} {
		e, ok := claudeEvent([]byte(tc.raw))
		if ok != (tc.status != "") || e.Status != tc.status {
			t.Fatal(tc, e, ok)
		}
	}
}
func TestClaudeConflicts(t *testing.T) {
	for _, raw := range []string{`null`, `{"hooks":null}`, `{"disableAllHooks":true}`, `{"hooks":{"Stop":42}}`,
		`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"python3 scripts/notify.py send completed"}]}]}}`} {
		if _, e := proposedClaude([]byte(raw), "/bin/notify"); e == nil {
			t.Fatal(raw)
		}
	}
	// Our name elsewhere (permission rules, project paths) is not a conflict.
	if _, e := proposedClaude([]byte(`{"permissions":{"allow":["Read(/src/ShinphonyAgent/**)"]}}`), "/bin/notify"); e != nil {
		t.Fatal(e)
	}
}

// Claude Code and other tools (MemSpace) rewrite settings.json after install.
// Our hooks are re-added or removed in place; other changes survive.
func TestClaudeMergesForeignEdits(t *testing.T) {
	s := fixtureStore(t)
	p := filepath.Join(s.dir, "settings.json")
	os.WriteFile(p, []byte(`{"theme":"dark"}`), 0600)
	cfg := func(exe string) {
		t.Helper()
		if e := s.configureAgentWith("claude", p, exe, true, proposedClaude, stripClaude); e != nil {
			t.Fatal(e)
		}
	}
	cfg(filepath.Join(s.dir, "agent-1"))
	// Another tool rewrote the file and dropped our hooks (seen on a user machine).
	other := `{"theme":"light","model":"opus","hooks":{"Stop":[{"hooks":[{"type":"command","command":"memspace hook claude"}]}]}}`
	os.WriteFile(p, []byte(other), 0600)
	cfg(filepath.Join(s.dir, "shinphony-hook-2"))
	cfg(filepath.Join(s.dir, "shinphony-hook-2"))
	raw, _ := os.ReadFile(p)
	text := string(raw)
	if strings.Count(text, "claude-hook-all") != len(claudeHookEvents) || strings.Contains(text, "agent-1") || !strings.Contains(text, "memspace hook claude") || !strings.Contains(text, `"light"`) {
		t.Fatal(text)
	}
	// Edited again while ours is present: still exactly one set of hooks.
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	doc["model"] = "sonnet"
	edited, _ := json.Marshal(doc)
	os.WriteFile(p, edited, 0600)
	cfg(filepath.Join(s.dir, "shinphony-hook-3"))
	raw, _ = os.ReadFile(p)
	if strings.Count(string(raw), "claude-hook-all") != len(claudeHookEvents) || !strings.Contains(string(raw), "shinphony-hook-3") {
		t.Fatal(string(raw))
	}
	// Uninstall after a further edit removes only ours.
	json.Unmarshal(raw, &doc)
	doc["theme"] = "dark-daltonized"
	edited, _ = json.Marshal(doc)
	os.WriteFile(p, edited, 0600)
	if e := s.uninstallAgentWith("claude", stripClaude); e != nil {
		t.Fatal(e)
	}
	raw, _ = os.ReadFile(p)
	if strings.Contains(string(raw), "claude-hook-all") || !strings.Contains(string(raw), "memspace hook claude") || !strings.Contains(string(raw), "dark-daltonized") {
		t.Fatal(string(raw))
	}
	if _, e := s.installRecord("claude"); !os.IsNotExist(e) {
		t.Fatal("record left behind")
	}
}

func TestStripClaudeUntouched(t *testing.T) {
	for _, raw := range []string{``, `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"x"}]}]}}`, "{\n  \"a\": 1\n}"} {
		if out, e := stripClaude([]byte(raw)); e != nil || string(out) != raw {
			t.Fatal(raw, string(out), e)
		}
	}
}
