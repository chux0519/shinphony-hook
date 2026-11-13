package notifier

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDetectedAgents(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", t.TempDir())
	codex := filepath.Join(home, "custom-codex")
	claude := filepath.Join(home, "custom-claude")
	t.Setenv("CODEX_HOME", codex)
	t.Setenv("CLAUDE_CONFIG_DIR", claude)
	m := Manager{Directory: filepath.Join(home, "notify")}
	got, err := m.DetectedAgents()
	if err != nil || len(got) != 0 {
		t.Fatalf("empty host: %v %v", got, err)
	}
	if err = os.Mkdir(codex, 0700); err != nil {
		t.Fatal(err)
	}
	got, err = m.DetectedAgents()
	if err != nil || !reflect.DeepEqual(got, []string{"codex"}) {
		t.Fatal(got, err)
	}
	if err = os.Mkdir(claude, 0700); err != nil {
		t.Fatal(err)
	}
	got, err = m.DetectedAgents()
	if err != nil || !reflect.DeepEqual(got, []string{"codex", "claude"}) {
		t.Fatal(got, err)
	}
	if _, err = os.Stat(filepath.Join(home, "notify")); !os.IsNotExist(err) {
		t.Fatal("detection mutated store")
	}
}
