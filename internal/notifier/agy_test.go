package notifier

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Antigravity keeps every hook in one named-group document. We own exactly one
// group; other groups, unknown fields and numbers survive install/uninstall.
func TestAgyInstallRoundTrip(t *testing.T) {
	foreign := `{"my-linter":{"PostToolUse":[{"matcher":"run_command","hooks":[{"type":"command","command":"./lint.sh","timeout":10}]}]},"notes":{"enabled":false,"Stop":[{"type":"command","command":"echo done"}]},"big":9007199254740993}`
	for name, original := range map[string]string{
		"missing": "",
		"empty":   "{}\n",
		"foreign": foreign,
	} {
		t.Run(name, func(t *testing.T) {
			s := fixtureStore(t)
			p := filepath.Join(s.dir, "hooks.json")
			if name != "missing" {
				os.WriteFile(p, []byte(original), 0600)
			}
			exe := filepath.Join(s.dir, "bin with spaces", "agent-1")
			for i := 0; i < 2; i++ {
				if e := s.configureAgy(p, exe, true); e != nil {
					t.Fatal(e)
				}
			}
			raw, _ := os.ReadFile(p)
			var doc map[string]json.RawMessage
			if json.Unmarshal(raw, &doc) != nil {
				t.Fatal(string(raw))
			}
			if strings.Count(string(raw), agySub) != len(agyEvents) || strings.Count(string(raw), `"`+agyGroup+`"`) != 1 {
				t.Fatal("wrong handler count or duplicate group:\n" + string(raw))
			}
			if name == "foreign" && (string(doc["big"]) != "9007199254740993" ||
				!strings.Contains(string(doc["my-linter"]), "./lint.sh") ||
				!strings.Contains(string(doc["notes"]), `"enabled": false`)) {
				t.Fatal("foreign content changed:\n" + string(raw))
			}
			assertAgyGroup(t, raw, exe)

			// A new immutable binary upgrades our commands only.
			exe2 := filepath.Join(s.dir, "shinphony-hook-2")
			if e := s.configureAgy(p, exe2, true); e != nil {
				t.Fatal(e)
			}
			raw, _ = os.ReadFile(p)
			assertAgyGroup(t, raw, exe2)
			if strings.Contains(string(raw), "agent-1") {
				t.Fatal("old executable left behind")
			}

			if e := s.uninstallAgy(); e != nil {
				t.Fatal(e)
			}
			raw, err := os.ReadFile(p)
			if name == "missing" {
				if !os.IsNotExist(err) {
					t.Fatal("created config left behind")
				}
				return
			}
			if err != nil || string(raw) != original {
				t.Fatal("not exact restore:", err, "\n"+string(raw))
			}
		})
	}
}

func assertAgyGroup(t *testing.T, raw []byte, exe string) {
	t.Helper()
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("invalid json")
	}
	var group map[string][]json.RawMessage
	if json.Unmarshal(doc[agyGroup], &group) != nil {
		t.Fatal("group missing or not an object of event arrays")
	}
	for _, event := range agyEvents {
		entries := group[event]
		if len(entries) != 1 {
			t.Fatal(event, "entries", len(entries))
		}
		var handler struct {
			Type    string `json:"type"`
			Command string `json:"command"`
			Timeout int    `json:"timeout"`
		}
		if agyToolEvents[event] {
			var entry struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Type    string `json:"type"`
					Command string `json:"command"`
					Timeout int    `json:"timeout"`
				} `json:"hooks"`
			}
			if json.Unmarshal(entries[0], &entry) != nil || entry.Matcher != agyToolMatcher || len(entry.Hooks) != 1 {
				t.Fatal(event, "tool entry shape")
			}
			handler.Type, handler.Command, handler.Timeout = entry.Hooks[0].Type, entry.Hooks[0].Command, entry.Hooks[0].Timeout
		} else if json.Unmarshal(entries[0], &handler) != nil {
			// Handlers of SessionStart/PreInvocation/PostInvocation/Stop are
			// plain command handlers, not matcher wrappers.
			t.Fatal(event, "plain entry shape")
		}
		if handler.Type != "command" || handler.Timeout != 6 || handler.Command != agyHookCommand("darwin", exe, event) {
			t.Fatal(event, handler)
		}
	}
}

// Paths with spaces and quotes, on each platform's documented shell.
func TestAgyHookCommandQuoting(t *testing.T) {
	posix := `'/Users/a b/bin/it'\''s/agent' agy-hook Stop`
	if got := agyHookCommand("darwin", "/Users/a b/bin/it's/agent", "Stop"); got != posix {
		t.Fatal(got)
	}
	// cmd.exe runs the command exactly as written; double quotes keep spaces
	// and avoid the PowerShell call operator used by other adapters.
	windows := `"C:\Users\a b\agent.exe" agy-hook PreToolUse`
	if got := agyHookCommand("windows", `C:\Users\a b\agent.exe`, "PreToolUse"); got != windows {
		t.Fatal(got)
	}
	if strings.Contains(agyHookCommand("windows", `C:\x\agent.exe`, "Stop"), "&") {
		t.Fatal("powershell convention used on windows")
	}
}

// Strip works inside our group only: a mixed entry keeps the other tools'
// handlers, a foreign group is byte-identical even when it copies our command.
func TestAgyStripPreservesForeignEntries(t *testing.T) {
	s := fixtureStore(t)
	doc := `{"shinphony":{"PreToolUse":[{"matcher":"ask_question","hooks":[{"command":"foreign-tool --keep"},{"command":"'/x/agent-1' agy-hook PreToolUse"}]}],"Stop":[{"type":"command","command":"'/x/agent-1' agy-hook Stop"}],"custom":"kept"}}`
	one, err := agyStrip([]byte(doc), "/x/agent-1")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]json.RawMessage
	json.Unmarshal(one, &parsed)
	if strings.Contains(string(one), agySub) || !strings.Contains(string(one), "foreign-tool --keep") ||
		!strings.Contains(string(one), `"custom": "kept"`) || !strings.Contains(string(one), "run_command") && strings.Contains(string(one), "ask_question") == false {
		t.Fatal(string(one))
	}
	foreign := `{"audit":{"Stop":[{"command":"'/x/agent-1' agy-hook Stop"}]}}`
	if out, e := agyStrip([]byte(foreign), "/x/agent-1"); e != nil || string(out) != foreign {
		t.Fatal("foreign group touched")
	}
	if out, e := agyStrip([]byte("{}"), "/x/agent-1"); e != nil || string(out) != "{}" {
		t.Fatal("empty document touched")
	}
	if e := s.uninstallAgy(); !os.IsNotExist(e) {
		t.Fatal("uninstall without an install record:", e)
	}
}

func TestAgyConflicts(t *testing.T) {
	for raw, want := range map[string]string{
		`null`:                            "invalid_agy_config",
		`[]`:                              "invalid_agy_config",
		`{"shinphony":42}`:                "invalid_agy_config",
		`{"shinphony":{"enabled":false}}`: "hooks_disabled",
		// We never replace another shinphony integration.
		`{"shinphony":{"Stop":[{"type":"command","command":"python3 notify.py"}]}}`: "existing_shinphony_config",
		`{"lint":{"Stop":[{"type":"command","command":"shinphony-old send"}]}}`:   "existing_shinphony_config",
	} {
		if _, e := proposedAgy([]byte(raw), "/bin/agent"); e == nil || e.Error() != want {
			t.Fatalf("%s: %v", raw, e)
		}
	}
	// A preflight install must not create or change the file.
	s := fixtureStore(t)
	p := filepath.Join(s.dir, "hooks.json")
	if e := s.configureAgy(p, "/bin/agent", false); e != nil {
		t.Fatal(e)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("preflight created the config")
	}
}

func TestAgyParseEvents(t *testing.T) {
	base := `"conversationId":"ec33ebf9-0cba-4100-8142-c61503f6c587","workspacePaths":["/src/hook"],"transcriptPath":"/secret/transcript.jsonl","modelName":"m"`
	for _, tc := range []struct {
		event string
		raw   string
		ok    bool
		check func(AgyHook) bool
	}{
		{"SessionStart", `{` + base + `,"lastUserInput":"fix the tests"}`, true, func(h AgyHook) bool {
			return h.Session == "ec33ebf9-0cba-4100-8142-c61503f6c587" && h.Cwd == "/src/hook" && h.Prompt == "fix the tests"
		}},
		{"PreInvocation", `{` + base + `,"invocationNum":3,"initialNumSteps":10,"lastUserInput":"fix the tests"}`, true, func(h AgyHook) bool {
			return h.Prompt == "fix the tests"
		}},
		{"PreToolUse", `{` + base + `,"toolCall":{"name":"ask_question","args":{"questions":[{"question":"Which file?","options":["a.go","b.go"],"is_multi_select":false}]}},"stepIdx":2}`, true, func(h AgyHook) bool {
			return h.Tool == "ask_question" && len(h.Questions) == 1 && h.Questions[0].Text == "Which file?" &&
				len(h.Questions[0].Options) == 2 && h.Questions[0].Options[1] == "b.go"
		}},
		{"PreToolUse", `{` + base + `,"toolCall":{"name":"ask_question","args":{"questions":[{"question":"Q","options":[{"label":"Yes"},{"label":"No"}]}]}}}`, true, func(h AgyHook) bool {
			return len(h.Questions) == 1 && h.Questions[0].Options[0] == "Yes"
		}},
		{"PreToolUse", `{` + base + `,"toolCall":{"name":"ask_permission","args":{"Action":"grant","Target":"read_file(/etc)","Reason":"needs config"}}}`, true, func(h AgyHook) bool {
			return h.Action == "grant" && h.Target == "read_file(/etc)" && h.Reason == "needs config"
		}},
		{"PreToolUse", `{` + base + `,"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf /"}}}`, true, func(h AgyHook) bool {
			return h.Tool == "run_command"
		}},
		{"PostToolUse", `{` + base + `,"toolCall":{"name":"ask_question","args":{}},"stepIdx":3,"error":""}`, true, func(h AgyHook) bool {
			return h.Tool == "ask_question"
		}},
		{"Stop", `{` + base + `,"executionNum":1,"terminationReason":"model_stop","error":"","fullyIdle":true}`, true, func(h AgyHook) bool {
			return h.Termination == "model_stop" && h.HasFullyIdle && h.FullyIdle
		}},
		{"Stop", `{` + base + `,"executionNum":2,"terminationReason":"model_stop","fullyIdle":false}`, true, func(h AgyHook) bool {
			return h.HasFullyIdle && !h.FullyIdle
		}},
		{"Stop", `{` + base + `,"terminationReason":"model_stop"}`, true, func(h AgyHook) bool { return !h.HasFullyIdle }},
		// The event name comes from the installed command, never from stdin.
		{"Stop", `{` + base + `,"hookEventName":"PreInvocation","fullyIdle":true}`, true, func(h AgyHook) bool { return h.Event == "Stop" }},
		// Unknown event, missing conversation, control characters, too large.
		{"PreCompact", `{` + base + `}`, false, nil},
		{"Stop", `{"workspacePaths":["/w"],"fullyIdle":true}`, false, nil},
		{"Stop", `{"conversationId":"","fullyIdle":true}`, false, nil},
		{"Stop", `{"conversationId":"a\nb","fullyIdle":true}`, false, nil},
	} {
		h, ok := ParseAgyHook(tc.event, []byte(tc.raw))
		if ok != tc.ok || (ok && tc.check != nil && !tc.check(h)) {
			t.Fatalf("%s %s: %+v %v", tc.event, tc.raw, h, ok)
		}
	}
	huge := []byte(`{"conversationId":"` + strings.Repeat("a", 300000) + `"}`)
	if _, ok := ParseAgyHook("Stop", huge); ok {
		t.Fatal("accepted an oversized payload")
	}
	// Multiple workspaces: the first is the project label, and nothing else
	// from the payload (transcript path, model) escapes the parser.
	h, ok := ParseAgyHook("SessionStart", []byte(`{"conversationId":"c","workspacePaths":["/one","/two"]}`))
	if !ok || h.Cwd != "/one" {
		t.Fatal(h, ok)
	}
}

// With only the CLI installed, ~/.gemini does not exist yet: the installer
// creates the shared parent privately instead of refusing, and preflight
// creates nothing.
func TestAgyInstallCreatesSharedParent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	m := Manager{Directory: filepath.Join(home, "creds")}
	exe := filepath.Join(home, "agent-1")
	if err := m.Configure("agy", exe, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".gemini")); !os.IsNotExist(err) {
		t.Fatal("preflight created the shared parent")
	}
	if err := m.Configure("agy", exe, true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(home, ".gemini"))
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("shared parent", err)
	}
	raw, err := os.ReadFile(agyConfigPath(home))
	if err != nil || !strings.Contains(string(raw), "agy-hook SessionStart") {
		t.Fatal(err)
	}
	if err = m.Uninstall("agy"); err != nil {
		t.Fatal(err)
	}
}

func TestAgyDetection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", t.TempDir())
	if agyDetected(home) {
		t.Fatal("detected without the CLI or its data directory")
	}
	// ~/.gemini is shared with the Gemini CLI; only agy's own directories count.
	if err := os.MkdirAll(filepath.Join(home, ".gemini", "config"), 0700); err != nil {
		t.Fatal(err)
	}
	if agyDetected(home) {
		t.Fatal("detected from the shared config directory")
	}
	m := Manager{Directory: filepath.Join(home, "creds")}
	if got, err := m.DetectedAgents(); err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".gemini", "antigravity-cli"), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := m.DetectedAgents(); err != nil || len(got) != 1 || got[0] != "agy" {
		t.Fatal(got, err)
	}
	// Explicit setup needs only the CLI: no per-user agy directory at all.
	os.RemoveAll(filepath.Join(home, ".gemini"))
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "agy"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	if !agyDetected(home) {
		t.Fatal("CLI on PATH not detected")
	}
	if got, err := m.DetectedAgents(); err != nil || len(got) != 1 || got[0] != "agy" {
		t.Fatal(got, err)
	}
	// An install records the agent for later refreshes.
	if err := m.Configure("agy", filepath.Join(home, "agent-1"), true); err != nil {
		t.Fatal(err)
	}
	if got, err := m.InstalledAgents(); err != nil || len(got) != 1 || got[0] != "agy" {
		t.Fatal(got, err)
	}
	raw, err := os.ReadFile(agyConfigPath(home))
	if err != nil || !strings.Contains(string(raw), "agent-1") {
		t.Fatal(err)
	}
	if err = m.Uninstall("agy"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(agyConfigPath(home)); !os.IsNotExist(err) {
		t.Fatal("uninstall left the created config behind")
	}
}
// A tool entry that mixes our handler with another tool's keeps the foreign
// handlers and its matcher; only our handler is removed.
func TestAgyMixedToolEntryPreservesForeignHandlers(t *testing.T) {
	raw := []byte(`{"shinphony":{"PreToolUse":[{"matcher":"ask_question","hooks":[{"command":"'/x/agent-1' agy-hook PreToolUse"},{"command":"foreign-tool --keep"}]},{"matcher":"browser_.*","hooks":[{"command":"foreign-only"}]}]}}`)
	got, err := agyStrip(raw, "/x/agent-1")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(got, &doc) != nil {
		t.Fatal(string(got))
	}
	var group map[string][]struct {
		Matcher string `json:"matcher"`
		Hooks   []struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if json.Unmarshal(doc[agyGroup], &group) != nil {
		t.Fatal(string(got))
	}
	if len(group["PreToolUse"]) != 2 {
		t.Fatal("foreign entry lost:", string(got))
	}
	if group["PreToolUse"][0].Matcher != "ask_question" || len(group["PreToolUse"][0].Hooks) != 1 ||
		group["PreToolUse"][0].Hooks[0].Command != "foreign-tool --keep" {
		t.Fatal("mixed entry not preserved:", string(got))
	}
	if group["PreToolUse"][1].Matcher != "browser_.*" || group["PreToolUse"][1].Hooks[0].Command != "foreign-only" {
		t.Fatal("unrelated entry changed:", string(got))
	}
	// A Stop entry written as a tool-style wrapper is not what we install, so it
	// is not ours; our plain Stop handler is removed.
	only := []byte(`{"shinphony":{"Stop":[{"type":"command","command":"'/x/agent-1' agy-hook Stop"}]}}`)
	if out, err := agyStrip(only, "/x/agent-1"); err != nil || string(out) != "{}" {
		t.Fatal(string(out), err)
	}
}

// Foreign named groups are never modified, whatever their commands look like.
func TestAgyForeignGroupsAreNeverModified(t *testing.T) {
	ours := "/x/shinphony-hook-" + strings.Repeat("b", 64)
	for _, foreign := range []string{
		`{"audit":{"Stop":[{"command":"echo agy-hook Stop"}]}}`,
		`{"audit":{"Stop":[{"command":"'/x/agent-` + strings.Repeat("a", 64) + `' agy-hook Stop"}]}}`,
		`{"audit":{"PreToolUse":[{"matcher":"x","hooks":[{"command":"'/x/agent-` + strings.Repeat("c", 64) + `' agy-hook PreToolUse"}]}]}}`,
	} {
		got, err := proposedAgy([]byte(foreign), ours)
		if err != nil {
			t.Fatal(foreign, err)
		}
		var doc map[string]json.RawMessage
		json.Unmarshal(got, &doc)
		if _, ok := doc["audit"]; !ok || !strings.Contains(string(got), "agy-hook") {
			t.Fatal("foreign group modified:", string(got))
		}
	}
	// Our exact command in another group would double every event: refuse.
	dup := `{"audit":{"Stop":[{"command":"` + agyHookCommand("darwin", ours, "Stop") + `"}]}}`
	strip := func(b []byte) ([]byte, error) { return agyStrip(b, ours) }
	if _, err := agyProposal("darwin", []string{ours}, []byte(dup), ours); err == nil ||
		!strings.Contains(err.Error(), "existing_shinphony_config") {
		t.Fatal("duplicate writer across groups accepted:", err)
	}
	_ = strip
	// A same-named group we cannot prove we own is a conflict, never a rewrite.
	unowned := `{"shinphony":{"Stop":[{"command":"` + agyHookCommand("darwin", ours, "Stop") + `"}]}}`
	if _, err := agyProposal("darwin", nil, []byte(unowned), ours); err == nil ||
		!strings.Contains(err.Error(), "existing_shinphony_config") {
		t.Fatal("unowned shinphony group accepted:", err)
	}
	// With journal evidence the same command is ours and is replaced in place.
	got, err := agyProposal("darwin", []string{ours}, []byte(unowned), ours)
	if err != nil || strings.Count(string(got), agySub) != len(agyEvents) {
		t.Fatal("owned group not upgraded:", err, string(got))
	}
}

// Windows cmd.exe expands %NAME% even inside double quotes and cannot carry
// quotes or line breaks: refuse those before creating or changing any config.
func TestAgyWindowsPathPreflight(t *testing.T) {
	for _, bad := range []string{
		`C:\Users\100%\shinphony-hook-` + strings.Repeat("a", 64) + `.exe`,
		`C:\Users\a"b\shinphony-hook-` + strings.Repeat("b", 64) + `.exe`,
		"C:\\Users\\a\nb\\shinphony-hook-" + strings.Repeat("c", 64) + ".exe",
		"C:\\Users\\a\rb\\shinphony-hook-" + strings.Repeat("d", 64) + ".exe",
		"relative\\shinphony-hook.exe",
	} {
		if err := agyPathError("windows", bad); err == nil {
			t.Fatal("accepted unsupported windows path", bad)
		}
		if _, err := agyProposal("windows", nil, nil, bad); err == nil {
			t.Fatal("proposal accepted unsupported windows path", bad)
		}
	}
	good := `C:\Program Files\Shinphony\shinphony-hook-` + strings.Repeat("e", 64) + `.exe`
	if err := agyPathError("windows", good); err != nil {
		t.Fatal(err)
	}
	raw, err := agyProposal("windows", nil, nil, good)
	if err != nil {
		t.Fatal(err)
	}
	var winDoc map[string]map[string][]struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(raw, &winDoc) != nil || len(winDoc[agyGroup]["Stop"]) != 1 ||
		winDoc[agyGroup]["Stop"][0].Command != `"`+good+`" agy-hook Stop` {
		t.Fatal("windows command not quoted as cmd.exe expects:", string(raw))
	}
	// POSIX keeps apostrophes through the documented '\'' escape and spaces.
	posix := "/Users/a b/it's/shinphony-hook-" + strings.Repeat("f", 64)
	if err := agyPathError("darwin", posix); err != nil || !agyOwned(agyHookCommand("darwin", posix, "PreInvocation"), posix) {
		t.Fatal(posix, err)
	}
	// Line breaks are refused on every platform.
	if agyPathError("darwin", "/x/a\nb/shinphony-hook-x") == nil {
		t.Fatal("accepted POSIX newline")
	}
}

// Preflight rejects an unsupported path without creating or changing anything.
func TestAgyUnsupportedPathCreatesNothing(t *testing.T) {
	s := fixtureStore(t)
	home := filepath.Join(filepath.Dir(s.dir), "home")
	p := filepath.Join(home, ".gemini", "config", "hooks.json")
	bad := filepath.Join(home, "100%", "agent-1")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(home, "existing.json"), []byte("{}"), 0600)
	// Only the Windows rule rejects "%"; force it through the explicit platform
	// proposal, then confirm the real installer leaves every path untouched.
	if _, err := agyProposal("windows", nil, nil, bad); err == nil {
		t.Fatal("windows percent path accepted")
	}
	if err := s.configureAgy(p, bad, true); err != nil {
		// On POSIX "%" is a legal path character, so this may succeed; the
		// preflight/apply contract is checked below with a newline instead.
		t.Log("posix percent path install:", err)
	}
	os.RemoveAll(filepath.Join(home, ".gemini"))
	newline := filepath.Join(home, "a\nb", "agent-1")
	if err := s.configureAgy(p, newline, true); err == nil || err.Error() != "unsupported_agent_path" {
		t.Fatal("newline path accepted", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".gemini")); !os.IsNotExist(err) {
		t.Fatal("unsupported path created configuration")
	}
}

// journalWithUpgrade rewrites the agy journal as the crash point: the new
// generation is journaled, the config on disk is still the old one.
func journalWithUpgrade(t *testing.T, s store, oldExe, newExe string, previousExe bool) {
	t.Helper()
	rec, err := s.installRecord("agy")
	if err != nil {
		t.Fatal(err)
	}
	desired, err := proposedAgy(rec.Before, newExe)
	if err != nil {
		t.Fatal(err)
	}
	rec.Schema = 3
	rec.PreviousAfter = rec.After
	rec.After = digest(desired)
	if previousExe {
		rec.PreviousExecutable = rec.Executable
	}
	rec.Executable = newExe
	raw, _ := json.Marshal(rec)
	if err := os.WriteFile(s.recordPath("agy"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func addForeignGroup(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("invalid config")
	}
	doc["audit"] = json.RawMessage(`{"Stop":[{"command":"foreign-tool --keep"}]}`)
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(path, out, 0600); err != nil {
		t.Fatal(err)
	}
	return out
}

// An interrupted upgrade (journaled new generation, old config) must be
// resumable, and a later uninstall must remove the old owned handlers even
// after another tool legitimately edited the file.
func TestAgyInterruptedUpgradeResumesThenUninstalls(t *testing.T) {
	s := fixtureStore(t)
	p := filepath.Join(s.dir, "hooks.json")
	oldExe := filepath.Join(s.dir, "agent-old")
	newExe := filepath.Join(s.dir, "agent-new")
	original := `{"foreign":{"Stop":[{"command":"keep-me"}]}}`
	if err := os.WriteFile(p, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.configureAgy(p, oldExe, true); err != nil {
		t.Fatal(err)
	}
	journalWithUpgrade(t, s, oldExe, newExe, true)
	// Resume the interrupted upgrade; the new generation is installed.
	if err := s.configureAgy(p, newExe, true); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), newExe) || strings.Contains(string(raw), oldExe) {
		t.Fatal("resume did not finish the upgrade:", string(raw))
	}
	rec, err := s.installRecord("agy")
	if err != nil || rec.Executable != newExe || rec.PreviousExecutable != oldExe {
		t.Fatal("journal lost the bounded previous generation:", rec, err)
	}
	addForeignGroup(t, p)
	if err := s.uninstallAgy(); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(p)
	if !strings.Contains(string(raw), "foreign-tool --keep") || !strings.Contains(string(raw), "keep-me") ||
		strings.Contains(string(raw), agySub) {
		t.Fatal("uninstall after a foreign edit left owned handlers or lost foreign ones:", string(raw))
	}
	if _, err := s.installRecord("agy"); !os.IsNotExist(err) {
		t.Fatal("journal left behind after a successful uninstall")
	}
}

// A journal written before the previous generation was recorded cannot name
// the handlers still on disk: uninstall must refuse and keep everything, and
// the exact journaled generation must still uninstall cleanly later.
func TestAgyInterruptedUpgradeLegacyJournalRefuses(t *testing.T) {
	s := fixtureStore(t)
	p := filepath.Join(s.dir, "hooks.json")
	oldExe := filepath.Join(s.dir, "agent-old")
	newExe := filepath.Join(s.dir, "agent-new")
	if err := s.configureAgy(p, oldExe, true); err != nil {
		t.Fatal(err)
	}
	oldGeneration, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	journalWithUpgrade(t, s, oldExe, newExe, false)
	edited := addForeignGroup(t, p)
	if err := s.uninstallAgy(); err == nil {
		t.Fatal("ambiguous uninstall reported success")
	}
	if _, err := s.installRecord("agy"); err != nil {
		t.Fatal("refusal lost the recovery journal:", err)
	}
	if raw, _ := os.ReadFile(p); !bytes.Equal(raw, edited) {
		t.Fatal("refusal changed the config")
	}
	// The exact journaled old generation can still be restored.
	rec, err := s.installRecord("agy")
	if err != nil {
		t.Fatal(err)
	}
	if digest(oldGeneration) != rec.PreviousAfter {
		t.Fatal("fixture no longer matches the previous generation")
	}
	if err := os.WriteFile(p, oldGeneration, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.uninstallAgy(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("restore did not remove the created config")
	}
}

// Repeated upgrades keep only the immediately previous generation as ownership
// evidence, still uninstall cleanly, and never touch foreign groups.
func TestAgyRepeatedUpgradeKeepsBoundedOwnership(t *testing.T) {
	s := fixtureStore(t)
	p := filepath.Join(s.dir, "hooks.json")
	exes := []string{filepath.Join(s.dir, "agent-1"), filepath.Join(s.dir, "agent-2"), filepath.Join(s.dir, "agent-3")}
	original := `{"notes":{"enabled":false,"Stop":[{"command":"echo mine"}]}}`
	if err := os.WriteFile(p, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	for _, exe := range exes {
		if err := s.configureAgy(p, exe, true); err != nil {
			t.Fatal(err)
		}
	}
	rec, err := s.installRecord("agy")
	if err != nil || rec.Executable != exes[2] || rec.PreviousExecutable != exes[1] {
		t.Fatal("ownership is not bounded to the last generation:", rec, err)
	}
	if raw, _ := os.ReadFile(p); strings.Contains(string(raw), exes[0]) || !strings.Contains(string(raw), exes[2]) {
		t.Fatal("config does not match the newest generation:", string(raw))
	}
	if err := s.uninstallAgy(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil || string(raw) != original {
		t.Fatal("not an exact restore:", err, string(raw))
	}
}
