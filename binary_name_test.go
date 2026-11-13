package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestManagedBinaryNames(t *testing.T) {
	data := []byte("isolated binary fixture")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	for _, prefix := range []string{managedPrefix, legacyPrefix} {
		for _, suffix := range []string{"", ".exe"} {
			name := filepath.Join(t.TempDir(), prefix+digest+suffix)
			got, ok := managedBinaryDigest(name)
			if !ok || got != digest || !matchesManagedBinary(name, data) {
				t.Fatalf("valid managed executable rejected: %s", name)
			}
			if matchesManagedBinary(name, []byte("tampered")) {
				t.Fatal("digest mismatch accepted", name)
			}
		}
	}
	for _, bad := range []string{
		commandName, commandName + ".exe", "shinphony-agent", "agent-x",
		managedPrefix + digest[:63], managedPrefix + digest + "0",
		managedPrefix + strings.ToUpper(digest), managedPrefix + strings.Repeat("z", 64),
		managedPrefix + digest + ".bak", "other-" + digest,
	} {
		if _, ok := managedBinaryDigest(bad); ok || matchesManagedBinary(bad, data) {
			t.Fatal("unmanaged/invalid executable accepted", bad)
		}
	}
}

func TestRenamePreservesStateAndServiceIdentity(t *testing.T) {
	if stateDirectoryName != ".shinphony-agent" {
		t.Fatal("rename must not abandon existing state")
	}
	dir := filepath.Join(t.TempDir(), stateDirectoryName)
	sum := sha256.Sum256([]byte(filepath.Clean(dir)))
	want := "net.potafree.shinphony.agent." + hex.EncodeToString(sum[:6])
	if serviceName(dir) != want {
		t.Fatal("rename would register a duplicate service")
	}
}

func TestHookRenameSubprocess(t *testing.T) {
	if os.Getenv("SHINPHONY_HOOK_TEST_CHILD") != "1" {
		return
	}
	hookCLI(os.Getenv("SHINPHONY_HOOK_TEST_KIND"), nil)
	os.Exit(0)
}

// Execute the actual hook entry in named immutable copies, not just a string
// parser. Both names must reach the same private IPC endpoint. No pairing,
// live agent configuration, service manager or external network is involved.
func TestRenamedAndLegacyHooksReachDaemon(t *testing.T) {
	dir := privateTemp(t)
	canonical, err := serviceExecutable(dir)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := managedBinaryDigest(canonical)
	legacy := filepath.Join(dir, legacyPrefix+digest)
	if runtime.GOOS == "windows" {
		legacy += ".exe"
	}
	data, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(legacy, data, 0700); err != nil {
		t.Fatal(err)
	}
	ln, err := listenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	received := make(chan agentEvent, 6)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event agentEvent
		if r.URL.Path != "/v1/agent-events" || json.NewDecoder(r.Body).Decode(&event) != nil || !event.valid() {
			http.Error(w, "invalid_event", 400)
			return
		}
		received <- event
		w.Write([]byte(`{"queued":true}`))
	})}
	go server.Serve(ln)
	t.Cleanup(func() { server.Close() })
	for _, binary := range []string{canonical, legacy} {
		for _, agent := range []string{"claude", "codex", "dsh"} {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestHookRenameSubprocess$")
			cmd.Env = append(os.Environ(), "SHINPHONY_HOOK_TEST_CHILD=1", "SHINPHONY_HOOK_TEST_KIND="+agent+"-hook-all")
			cmd.Stdin = strings.NewReader(`{"hook_event_name":"Stop","session_id":"rename-test","last_assistant_message":"Fixture passed"}`)
			output, err := cmd.CombinedOutput()
			cancel()
			if err != nil || strings.TrimSpace(string(output)) != "{}" {
				t.Fatalf("%s %s: %s (%v)", binary, agent, output, err)
			}
			select {
			case event := <-received:
				if event.Agent != agent || event.Kind != "stop" {
					t.Fatal(event)
				}
			default:
				t.Fatal("hook silently skipped the renamed executable", binary, agent)
			}
		}
	}
}
