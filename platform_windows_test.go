package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsPrivateACL(t *testing.T) {
	dir := privateTemp(t)
	if err := privatePath(dir, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "inherited.txt")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := privatePath(path, false); err != nil {
		t.Fatal("private inherited ACL", err)
	}
	broad := t.TempDir()
	if err := privatePath(broad, true); err == nil {
		t.Fatal("default broad ACL accepted")
	}
}
