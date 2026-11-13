package main

import (
	"net.potafree/shinphony/hook/internal/notifier"
	"path/filepath"
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
