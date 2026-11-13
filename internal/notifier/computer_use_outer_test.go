package notifier

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func outerFixture(t *testing.T) (store, string, []byte, []byte) {
	t.Helper()
	s := fixtureStore(t)
	p := filepath.Join(s.dir, "config.toml")
	callback := "/Users/test/Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient"
	original := []byte("# user comment\nnotify = ['" + callback + "', 'turn-ended']\nmodel = 'test'\n[features]\nfoo = true\n")
	if err := os.WriteFile(p, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.configureCodex(p, filepath.Join(s.dir, "old-agent"), true); err != nil {
		t.Fatal(err)
	}
	managed, _ := os.ReadFile(p)
	args, _ := notifyArgs(managed)
	raw, _ := json.Marshal(args)
	wrapped, err := replaceNotify(managed, []string{callback, "turn-ended", "--previous-notify", string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, wrapped, 0600); err != nil {
		t.Fatal(err)
	}
	return s, p, original, wrapped
}

func TestAdoptComputerUseOuterRoundTrip(t *testing.T) {
	s, p, original, wrapped := outerFixture(t)
	exe := filepath.Join(s.dir, "new-agent")
	recordBefore, _ := os.ReadFile(s.recordPath("codex"))
	if err := s.configureCodex(p, exe, false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	recBytes, _ := os.ReadFile(s.recordPath("codex"))
	if !bytes.Equal(b, wrapped) || !bytes.Equal(recBytes, recordBefore) {
		t.Fatal("dry run mutated files")
	}
	for _, name := range []string{"new-agent", "new-agent", "next-agent"} {
		exe = filepath.Join(s.dir, name)
		if err := s.configureCodex(p, exe, true); err != nil {
			t.Fatal(err)
		}
		b, _ = os.ReadFile(p)
		args, err := notifyArgs(b)
		if err != nil || len(args) != 4 || !ComputerUseCommand(args[:2]) || args[2] != "--previous-notify" {
			t.Fatal("outer callback lost")
		}
		var nested []string
		if json.Unmarshal([]byte(args[3]), &nested) != nil || !reflect.DeepEqual(nested, []string{exe, "codex-notify-all"}) {
			t.Fatal("duplicated or incorrect callback")
		}
	}
	if err := s.uninstallCodex(); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p)
	if !bytes.Equal(b, original) {
		t.Fatal("uninstall lost original callback/comments")
	}
}

func TestAdoptComputerUseRejectsChanges(t *testing.T) {
	for _, kind := range []string{"nested-command", "callback", "malformed-json"} {
		t.Run(kind, func(t *testing.T) {
			s, p, _, wrapped := outerFixture(t)
			args, _ := notifyArgs(wrapped)
			switch kind {
			case "nested-command":
				args[3] = `["/tmp/unknown", "codex-notify-all"]`
				wrapped, _ = replaceNotify(wrapped, args)
			case "callback":
				args[0] = "/tmp/unknown"
				wrapped, _ = replaceNotify(wrapped, args)
			case "malformed-json":
				args[3] = "not json"
				wrapped, _ = replaceNotify(wrapped, args)
			}
			os.WriteFile(p, wrapped, 0600)
			prior, _ := os.ReadFile(s.recordPath("codex"))
			if err := s.configureCodex(p, filepath.Join(s.dir, "new-agent"), true); err == nil {
				t.Fatal("accepted unknown edits")
			}
			got, _ := os.ReadFile(p)
			rec, _ := os.ReadFile(s.recordPath("codex"))
			if !bytes.Equal(got, wrapped) || !bytes.Equal(rec, prior) {
				t.Fatal("rejection changed files")
			}
		})
	}
}

func TestAdoptComputerUseInterruptedJournal(t *testing.T) {
	s, p, _, wrapped := outerFixture(t)
	rec, err := s.installRecord("codex")
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(s.dir, "new-agent")
	updated, desired, err := adoptComputerUseOuter(wrapped, rec, exe)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(updated)
	os.WriteFile(s.recordPath("codex"), raw, 0600)
	if err = s.configureCodex(p, filepath.Join(s.dir, "different-agent"), true); err == nil {
		t.Fatal("different installer resumed pending transaction")
	}
	if err = s.configureCodex(p, exe, true); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, desired) {
		t.Fatal("failed to recover config commit")
	}
}

func TestAdoptComputerUseAroundDirectNotify(t *testing.T) {
	s := fixtureStore(t)
	p := filepath.Join(s.dir, "config.toml")
	os.WriteFile(p, []byte("# keep\nmodel = 'test'\n"), 0600)
	if err := s.configureCodex(p, filepath.Join(s.dir, "old"), true); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(p)
	nested, _ := notifyArgs(current)
	raw, _ := json.Marshal(nested)
	callback := "/Users/test/Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient"
	wrapped, err := replaceNotify(current, []string{callback, "turn-ended", "--previous-notify", string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(p, wrapped, 0600)
	if err = s.configureCodex(p, filepath.Join(s.dir, "new"), true); err != nil {
		t.Fatal(err)
	}
	if err = s.uninstallCodex(); err != nil {
		t.Fatal(err)
	}
	current, _ = os.ReadFile(p)
	args, _ := notifyArgs(current)
	if !reflect.DeepEqual(args, []string{callback, "turn-ended"}) {
		t.Fatal("new Computer Use callback was removed")
	}
}

// Explicit opt-in, read-only check against the operator's real wrapper. Never
// mutate live config or reveal contents; normal CI does not read HOME configs.
func TestLiveComputerUseAdoptionReadOnly(t *testing.T) {
	if os.Getenv("SHINPHONY_TEST_LIVE_CU") != "1" {
		t.Skip("operator opt-in required")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	s := store{dir: filepath.Join(home, ".shinphony-notify")}
	rec, err := s.installRecord("codex")
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := configRead(rec.Path)
	if err != nil {
		t.Fatal(err)
	}
	_, desired, err := adoptComputerUseOuter(current, rec, "/test/agent")
	if err != nil {
		t.Fatal("real wrapper not recognized:", err)
	}
	args, err := notifyArgs(desired)
	if err != nil || len(args) != 4 {
		t.Fatal("invalid proposal")
	}
}

// The Mac mini case: Computer Use wraps an older helper binary and Codex has
// since rewritten unrelated settings (model, project trust, a new table).
func TestCodexEditsAroundComputerUseWrapper(t *testing.T) {
	s, p, _, wrapped := outerFixture(t)
	edited := bytes.Replace(wrapped, []byte("model = 'test'"), []byte("model = 'other'"), 1)
	edited = bytes.Replace(edited, []byte("foo = true"), []byte("foo = false"), 1)
	edited = append(edited, []byte("[projects.\"/tmp/x\"]\ntrust_level = \"trusted\"\n")...)
	os.WriteFile(p, edited, 0600)
	exe := filepath.Join(s.dir, "new-agent")
	if err := s.configureCodex(p, exe, true); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	args, _ := notifyArgs(got)
	if len(args) != 4 || !ComputerUseCommand(args[:2]) || !strings.Contains(args[3], "new-agent") {
		t.Fatalf("unexpected notify %q", args)
	}
	for _, keep := range []string{"model = 'other'", "foo = false", "trust_level", "# user comment"} {
		if !strings.Contains(string(got), keep) {
			t.Fatalf("lost %q", keep)
		}
	}
	if err := s.configureCodex(p, exe, true); err != nil {
		t.Fatal("rerun:", err)
	}
	if err := s.uninstallCodex(); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(p)
	args, _ = notifyArgs(got)
	if !ComputerUseCommand(args) || !strings.Contains(string(got), "model = 'other'") || !strings.Contains(string(got), "trust_level") {
		t.Fatalf("uninstall lost settings: %q", got)
	}
}
