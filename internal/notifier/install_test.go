package notifier

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexInstallRoundTrip(t *testing.T) {
	s := fixtureStore(t)
	dir := filepath.Join(s.dir, "codex")
	if e := makePrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "config.toml")
	original := []byte("# keep this\nmodel = 'example'\n[features]\nfoo = true\n")
	if e := os.WriteFile(p, original, 0600); e != nil {
		t.Fatal(e)
	}
	exe := filepath.Join(s.dir, "bin with spaces", "shinphony-notify")
	if e := s.configureCodex(p, exe, false); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	if string(b) != string(original) {
		t.Fatal("preflight mutated config")
	}
	for i := 0; i < 2; i++ {
		if e := s.configureCodex(p, exe, true); e != nil {
			t.Fatal(e)
		}
	}
	b, _ = os.ReadFile(p)
	if strings.Count(string(b), "codex-notify-all") != 1 || !strings.HasSuffix(string(b), string(original)) {
		t.Fatal("lost config")
	}
	if e := s.uninstallCodex(); e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(p)
	if string(b) != string(original) {
		t.Fatal("not restored")
	}
}
func TestCodexConflictAndEditProtection(t *testing.T) {
	for _, original := range []string{"notify = ['other-tool']\n", "invalid = [", "notify = ['shinphony-old-adapter']\n"} {
		t.Run(original, func(t *testing.T) {
			s := fixtureStore(t)
			p := filepath.Join(s.dir, "config.toml")
			os.WriteFile(p, []byte(original), 0600)
			if e := s.configureCodex(p, filepath.Join(s.dir, "notify"), true); e == nil {
				t.Fatal("accepted conflict")
			}
			b, _ := os.ReadFile(p)
			if string(b) != original {
				t.Fatal("overwrote conflict")
			}
		})
	}
	s := fixtureStore(t)
	p := filepath.Join(s.dir, "config.toml")
	exe := filepath.Join(s.dir, "notify")
	if e := s.configureCodex(p, exe, true); e != nil {
		t.Fatal(e)
	}
	// The user removed our entry by hand: uninstall keeps their file as is.
	os.WriteFile(p, []byte("# edited\n"), 0600)
	if e := s.uninstallCodex(); e != nil {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(p); string(b) != "# edited\n" {
		t.Fatal("overwrote user edit")
	}
	if _, e := os.Stat(s.recordPath("codex")); !os.IsNotExist(e) {
		t.Fatal("record kept")
	}
	// A notify entry that is not ours is never replaced.
	if e := s.configureCodex(p, exe, true); e != nil {
		t.Fatal(e)
	}
	foreign := []byte("notify = ['/opt/other/tool', 'turn-ended']\nmodel = 'x'\n")
	os.WriteFile(p, foreign, 0600)
	if e := s.configureCodex(p, exe, true); e == nil {
		t.Fatal("replaced a foreign notify")
	}
	// Nothing of ours is left to remove; the file must stay untouched.
	_ = s.uninstallCodex()
	if b, _ := os.ReadFile(p); !bytes.Equal(b, foreign) {
		t.Fatal("changed a foreign notify")
	}
}
func TestCodexMissingDirectoryAndResume(t *testing.T) {
	s := fixtureStore(t)
	p := filepath.Join(s.dir, "codex", "config.toml")
	exe := filepath.Join(s.dir, "notify")
	if e := s.configureCodex(p, exe, false); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Dir(p)); !os.IsNotExist(e) {
		t.Fatal("preflight created codex directory")
	}
	if e := s.configureCodex(p, exe, true); e != nil {
		t.Fatal(e)
	}
	os.Remove(p) // simulate crash between journal and config commit
	if e := s.configureCodex(p, exe, true); e != nil {
		t.Fatal(e)
	}
	if e := s.uninstallCodex(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("created original absent config")
	}
}
