//go:build darwin || linux

package notifier

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectCredentialSymlinkAndBroadMode(t *testing.T) {
	s := fixtureStore(t)
	if e := s.saveNew("phone", fixtureCredential()); e != nil {
		t.Fatal(e)
	}
	p, _ := s.path("phone")
	os.Chmod(p, 0644)
	if _, e := s.load("phone"); e == nil {
		t.Fatal("read public credential")
	}
	os.Chmod(p, 0600)
	q, _ := s.path("alias")
	if e := os.Symlink(p, q); e != nil {
		t.Fatal(e)
	}
	if _, e := s.load("alias"); e == nil {
		t.Fatal("read symlink")
	}
	if e := os.Link(p, filepath.Join(s.dir, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.load("phone"); e == nil {
		t.Fatal("read hard-linked credential")
	}
}

func TestGroupWritableAgentDirectoryInsidePrivateHome(t *testing.T) {
	home := t.TempDir()
	os.Chmod(home, 0700)
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".codex")
	os.Mkdir(dir, 0775)
	os.Chmod(dir, 0775)
	if e := checkConfigParents(dir); e != nil {
		t.Fatal(e)
	}
	// Config exception must never relax credential-directory requirements.
	if e := checkPrivate(dir, true); e == nil {
		t.Fatal("accepted broad credential permissions")
	}
	os.Chmod(home, 0755)
	if e := checkConfigParents(dir); e == nil {
		t.Fatal("accepted publicly traversable group-writable config")
	}
}
func TestRejectStoreSymlink(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "target"), 0700)
	os.Symlink(filepath.Join(root, "target"), filepath.Join(root, "alias"))
	s := store{filepath.Join(root, "alias")}
	if e := s.initialize(); e == nil {
		t.Fatal("accepted symlink directory")
	}
}
