package notifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagedHookUpgradeAndInterruptedResume(t *testing.T) {
	for _, agent := range []string{"codex", "claude"} {
		t.Run(agent, func(t *testing.T) {
			s := fixtureStore(t)
			p := filepath.Join(s.dir, "config")
			original := []byte("# original\n")
			propose := proposedCodex
			if agent == "claude" {
				original = []byte(`{"permissions":{"defaultMode":"default"}}`)
				propose = proposedClaude
			}
			os.WriteFile(p, original, 0600)
			oldExe := filepath.Join(s.dir, "old-helper")
			newExe := filepath.Join(s.dir, "agent-new")
			if err := s.configureAgent(agent, p, oldExe, true, propose); err != nil {
				t.Fatal(err)
			}
			oldConfig, _ := os.ReadFile(p)
			if err := s.configureAgent(agent, p, newExe, true, propose); err != nil {
				t.Fatal(err)
			}
			newConfig, _ := os.ReadFile(p)
			if strings.Contains(string(newConfig), "old-helper") || !strings.Contains(string(newConfig), "agent-new") {
				t.Fatal("not migrated")
			}
			rec, err := s.installRecord(agent)
			if err != nil || rec.Schema != 2 {
				t.Fatal(rec, err)
			}
			// Journal committed but config rename lost: replay only known old hash.
			os.WriteFile(p, oldConfig, 0600)
			if err = s.configureAgent(agent, p, newExe, true, propose); err != nil {
				t.Fatal(err)
			}
			if err = s.uninstallAgent(agent); err != nil {
				t.Fatal(err)
			}
			restored, _ := os.ReadFile(p)
			if string(restored) != string(original) {
				t.Fatal("lost original")
			}
		})
	}
}
func TestMigrationKeepsUserEdit(t *testing.T) {
	s := fixtureStore(t)
	p := filepath.Join(s.dir, "config")
	exe := filepath.Join(s.dir, "old-helper")
	if err := s.configureCodex(p, exe, true); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(p)
	os.WriteFile(p, append(current, []byte("# user edit\n")...), 0600)
	newExe := filepath.Join(s.dir, "agent-new")
	if err := s.configureCodex(p, newExe, true); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	args, _ := notifyArgs(got)
	if !strings.Contains(string(got), "# user edit") || len(args) != 2 || args[0] != newExe {
		t.Fatalf("edit lost or entry not moved: %q", got)
	}
	if err := s.configureCodex(p, newExe, true); err != nil {
		t.Fatal("rerun:", err)
	}
	if err := s.uninstallCodex(); err != nil {
		t.Fatal(err)
	}
	if got, _ = os.ReadFile(p); string(got) != "# user edit\n" {
		t.Fatalf("uninstall did not keep only the user edit: %q", got)
	}
	if err := s.configureCodex(p, exe, true); err != nil {
		t.Fatal(err)
	}
	// Invalid journal versions are never accepted as authority to overwrite.
	rec, _ := s.installRecord("codex")
	rec.Schema = 999
	raw, _ := json.Marshal(rec)
	os.WriteFile(s.recordPath("codex"), raw, 0600)
	if _, err := s.installRecord("codex"); err == nil {
		t.Fatal("invalid schema")
	}
}
