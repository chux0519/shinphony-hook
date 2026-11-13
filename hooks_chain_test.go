package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestChainPreservesOriginalWhenDaemonUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("macOS callback")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient")
	if err := os.MkdirAll(filepath.Dir(exe), 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "args")
	t.Setenv("CHAIN_TEST_OUTPUT", output)
	script := "#!/bin/sh\nprintf '%s\\n' \"$#\" \"$1\" \"$2\" > \"$CHAIN_TEST_OUTPUT\"\nexit 7\n"
	if err := os.WriteFile(exe, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]string{exe, "turn-ended"})
	payload := `{"type":"agent-turn-complete","turn-id":"fixture","last-assistant-message":"space ; $(never-run) 中文"}`
	hookCLI("codex-notify-chain", []string{base64.RawURLEncoding.EncodeToString(raw), payload})
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "2\nturn-ended\n"+payload+"\n" {
		t.Fatal("argument boundaries or payload changed")
	}
	// A stalled callback cannot indefinitely block the Codex completion hook.
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexec sleep 20\n"), 0700); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	hookCLI("codex-notify-chain", []string{base64.RawURLEncoding.EncodeToString(raw), payload})
	if time.Since(start) > 4*time.Second {
		t.Fatal("callback not bounded")
	}
}
