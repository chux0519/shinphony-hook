package main

import (
	"net.potafree/shinphony/hook/internal/notifier"
	"strings"
	"path/filepath"
	"os"
	"testing"
)

func TestAutoSetupNoAgentsFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, "absent-codex"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "absent-claude"))
	err := configureSetupAgents(notifier.Manager{Directory: filepath.Join(home, "notify")}, "auto", "/not/run")
	if err == nil || err.Error() != "no_supported_agents" {
		t.Fatal(err)
	}
	j := setupRequest{ID: "test-auto", Agent: "auto", Profile: "phone", Host: "host", Lane: "sandbox"}
	if !j.valid() {
		t.Fatal("auto rejected")
	}
}

// Explicit and automatic setup both work for agy when only its CLI is
// present: the installer creates ~/.gemini/config/hooks.json itself.
func TestAutoSetupAgyFromCLIOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, "absent-codex"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "absent-claude"))
	t.Setenv("DSH_HOME", filepath.Join(home, "absent-dsh"))
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "agy"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	exe := filepath.Join(home, "shinphony-hook-"+strings.Repeat("a", 64))
	m := notifier.Manager{Directory: filepath.Join(home, "notify")}
	if err := configureSetupAgents(m, "auto", exe); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".gemini", "config", "hooks.json"))
	if err != nil || !strings.Contains(string(raw), "agy-hook Stop") {
		t.Fatal(err)
	}
	if err = m.Uninstall("agy"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(home, ".gemini", "config", "hooks.json")); !os.IsNotExist(err) {
		t.Fatal("uninstall left the created config")
	}
	// Explicit setup works the same way after the uninstall.
	if err = configureSetupAgents(m, "agy", exe); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(home, ".gemini", "config", "hooks.json")); err != nil {
		t.Fatal(err)
	}
}
