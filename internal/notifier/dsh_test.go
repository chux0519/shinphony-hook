package notifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDSHInstallRoundTrip(t *testing.T) {
	for name, original := range map[string]string{
		"missing": "",
		"empty":   "# my overrides\n[]\n",
		"block":   "- insert:\n    - id: mine\n      name: \"some-plugin\"",
	} {
		t.Run(name, func(t *testing.T) {
			s := fixtureStore(t)
			home := filepath.Join(filepath.Dir(s.dir), "dshhome")
			if e := os.Mkdir(home, 0700); e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(home, "cordis.patch.yml")
			if name != "missing" {
				os.WriteFile(p, []byte(original), 0600)
			}
			exe := filepath.Join(s.dir, "a b", "agent-1")
			for i := 0; i < 2; i++ {
				if e := s.configureDSH(p, exe, true); e != nil {
					t.Fatal(e)
				}
			}
			raw, _ := os.ReadFile(p)
			text := string(raw)
			if strings.Count(text, dshBlockBegin) != 1 || !strings.Contains(text, `configPath: `+jsonString(s.dshHooksPath())) {
				t.Fatal(text)
			}
			if strings.Contains(text, "[]") || (name == "block" && !strings.HasPrefix(text, original+"\n")) {
				t.Fatal("did not keep the list well-formed:\n" + text)
			}
			assertDSHHook(t, s, exe)

			// Upgrading to a new immutable binary only rewrites our hooks file.
			exe2 := filepath.Join(s.dir, "shinphony-hook-2")
			if e := s.configureDSH(p, exe2, true); e != nil {
				t.Fatal(e)
			}
			if again, _ := os.ReadFile(p); string(again) != text {
				t.Fatal("patch changed on upgrade")
			}
			assertDSHHook(t, s, exe2)

			if e := s.uninstallDSH(); e != nil {
				t.Fatal(e)
			}
			raw, err := os.ReadFile(p)
			if name == "missing" {
				if !os.IsNotExist(err) {
					t.Fatal("created patch file left behind")
				}
			} else if string(raw) != original {
				t.Fatal("not exact restore")
			}
			if _, err := os.Stat(s.dshHooksPath()); !os.IsNotExist(err) {
				t.Fatal("hooks file left behind")
			}
		})
	}
}

func jsonString(s string) string { b, _ := json.Marshal(s); return string(b) }

func assertDSHHook(t *testing.T, s store, exe string) {
	t.Helper()
	raw, err := readPrivate(s.dshHooksPath())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hooks map[string][]struct {
			Hooks []struct{ Type, Command string }
		}
	}
	if json.Unmarshal(raw, &doc) != nil || len(doc.Hooks) != 3 {
		t.Fatal(string(raw))
	}
	for _, event := range []string{"SessionStart", "UserPromptSubmit", "Stop"} {
		if len(doc.Hooks[event]) != 1 {
			t.Fatal(event, string(raw))
		}
		h := doc.Hooks[event][0].Hooks
		if len(h) != 1 || h[0].Type != "command" || !strings.Contains(h[0].Command, exe) || !strings.HasSuffix(h[0].Command, " dsh-hook-all") {
			t.Fatal(string(raw))
		}
		if runtime.GOOS != "windows" && h[0].Command != "'"+exe+"' dsh-hook-all" {
			t.Fatal(h[0].Command)
		}
	}
}

func TestDSHRefusals(t *testing.T) {
	propose := proposedDSH("/x/dsh-hooks.json")
	if _, e := propose([]byte("[{insert: []}]"), "/bin/agent"); e == nil {
		t.Fatal("rewrote a flow list")
	}
	// An earlier block of ours is replaced, not duplicated.
	out, e := propose([]byte("- a: 1\n"+dshBlockBegin+"\n- insert: []\n"+dshBlockEnd+"\n- b: 2\n"), "/bin/agent")
	if e != nil || strings.Count(string(out), dshBlockBegin) != 1 || !strings.HasPrefix(string(out), "- a: 1\n- b: 2\n"+dshBlockBegin) {
		t.Fatal(string(out), e)
	}
	// A user's own path containing the name is fine.
	if _, e := propose([]byte("- insert:\n    - id: x\n      config:\n        root: /src/ShinphonyAgent\n"), "/bin/agent"); e != nil {
		t.Fatal(e)
	}
}

// MemSpace and users add rows to the same patch file after we install.
func TestDSHMergesForeignEdits(t *testing.T) {
	s := fixtureStore(t)
	p := filepath.Join(filepath.Dir(s.dir), "cordis.patch.yml")
	os.WriteFile(p, []byte("# mine\n[]\n"), 0600)
	if e := s.configureDSH(p, filepath.Join(s.dir, "agent-1"), true); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(p)
	edited := append(raw, []byte("- remove: [x]\n")...)
	os.WriteFile(p, edited, 0600)
	if e := s.configureDSH(p, filepath.Join(s.dir, "shinphony-hook-2"), true); e != nil {
		t.Fatal(e)
	}
	if now, _ := os.ReadFile(p); string(now) != string(edited) {
		t.Fatal("rewrote an edited file that already has our row:\n" + string(now))
	}
	assertDSHHook(t, s, filepath.Join(s.dir, "shinphony-hook-2"))
	if e := s.uninstallDSH(); e != nil {
		t.Fatal(e)
	}
	if now, _ := os.ReadFile(p); string(now) != "# mine\n- remove: [x]\n" {
		t.Fatalf("%q", now)
	}
	// Only comments left: DSH needs an explicit empty list.
	if out, _ := stripDSHForUninstall([]byte("# mine\n" + dshBlockBegin + "\n" + dshBlockEnd + "\n")); string(out) != "# mine\n[]\n" {
		t.Fatalf("%q", out)
	}
}

func TestDSHHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PATH", "")
	t.Setenv("DSH_HOME", "")
	os.Unsetenv("DSH_HOME")
	if got := dshHome(home); got != filepath.Join(home, ".dsh") {
		t.Fatal(got)
	}
	bin := filepath.Join(home, ".local", "bin")
	os.MkdirAll(bin, 0700)
	data := filepath.Join(home, "llc", "dsh", "data")
	os.WriteFile(filepath.Join(bin, "dsh"), []byte("#!/bin/sh\nexport DSH_HOME="+data+"\nexec node bin.js \"$@\"\n"), 0700)
	if got := dshHome(home); got != data {
		t.Fatal(got)
	}
	// Unexpanded variables are not guessed at.
	os.WriteFile(filepath.Join(bin, "dsh"), []byte("#!/bin/sh\nexport DSH_HOME=$HOME/x\n"), 0700)
	if got := dshHome(home); got != filepath.Join(home, ".dsh") {
		t.Fatal(got)
	}
	t.Setenv("DSH_HOME", "/explicit")
	if got := dshHome(home); got != "/explicit" {
		t.Fatal(got)
	}
}

func TestDSHEvents(t *testing.T) {
	// Exactly what the bridge sent from a real DSH 0.2.0-rc.2 turn. A turn
	// ending is not task completion, so it produces no event.
	raw := `{"session_id":"session-77ad53e0","transcript_path":"","cwd":"/w","hook_event_name":"Stop","stop_hook_active":false}`
	for _, raw := range []string{raw, ``, `{}`, `{"hook_event_name":"SubagentStop","session_id":"s"}`} {
		if _, _, ok := Extract("dsh-hook-all", []byte(raw)); ok {
			t.Fatal(raw)
		}
	}
}
