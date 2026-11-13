package notifier

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Real CLI dispatch, filesystem transaction, pairing and HTTP transport with
// an isolated relay fixture. Never consumes production registrations or agents.
func TestOneClickLifecycle(t *testing.T) {
	home := fixtureStore(t).dir
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "claude"))
	var exchanges, events atomic.Int32
	r := fixtureRelay(t, func(w http.ResponseWriter, q *http.Request) {
		if strings.HasSuffix(q.URL.Path, "/pair/exchange") {
			exchanges.Add(1)
			json.NewEncoder(w).Encode(map[string]string{"hostId": "host-one", "hostToken": strings.Repeat("A", 43)})
		} else {
			events.Add(1)
			w.Write([]byte(`{"accepted":true}`))
		}
	})
	call := func(input string, args ...string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := run(args, strings.NewReader(input), &out, &errOut, r); code != 0 {
			t.Fatalf("%v: %s", args, errOut.String())
		}
		return out.String()
	}
	for _, agent := range []string{"codex", "claude"} {
		call("", "preflight-"+agent)
	}
	if !strings.Contains(call("", "profile-status", "phone", "production", "host-one"), "false") {
		t.Fatal("unexpected profile")
	}
	call(strings.Repeat("B", 43), "pair", "phone", "production", "host-one")
	for _, agent := range []string{"codex", "claude"} {
		call("", "install-"+agent)
		call("", "install-"+agent)
	}
	call("", "send", "phone", "completed")
	call("", "codex-notify-all", `{"type":"agent-turn-complete","thread-id":"s","turn-id":"t"}`)
	call(`{"hook_event_name":"Stop","session_id":"s"}`, "claude-hook-all")
	call(`{"hook_event_name":"Notification","session_id":"s","notification_type":"permission_prompt"}`, "claude-hook-all")
	if exchanges.Load() != 1 || events.Load() != 2 {
		t.Fatal(exchanges.Load(), events.Load())
	}
	for _, agent := range []string{"codex", "claude"} {
		call("", "uninstall-"+agent)
	}
	call("", "reset-profile", "phone")
	if _, e := os.Stat(filepath.Join(home, ".shinphony-notify", "phone.json")); !os.IsNotExist(e) {
		t.Fatal("reset failed")
	}
}
