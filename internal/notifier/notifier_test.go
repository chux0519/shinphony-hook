package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureStore(t *testing.T) store {
	t.Helper()
	home := t.TempDir()
	if runtime.GOOS != "windows" {
		if e := os.Chmod(home, 0700); e != nil {
			t.Fatal(e)
		}
	}
	s := store{filepath.Join(home, "private")}
	if e := s.initialize(); e != nil {
		t.Fatal(e)
	}
	return s
}
func fixtureCredential() credential {
	return credential{1, "production", "host-one", strings.Repeat("A", 43)}
}
func fixtureRelay(t *testing.T, h http.HandlerFunc) relay {
	t.Helper()
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	r := newRelay()
	r.origin = server.URL
	return r
}
func TestEventContracts(t *testing.T) {
	a, ok := codexEvent([]byte(`{"type":"agent-turn-complete","thread-id":"thread","turn-id":"turn","last-assistant-message":"SECRET"}`), true)
	if ok || a.Status != "" {
		t.Fatal(a)
	}
	b, ok := codexEvent([]byte(`{"hook_event_name":"Stop","session_id":"thread","turn_id":"turn","transcript_path":"/DO_NOT_READ"}`), false)
	if ok || a != b || strings.Contains(a.ID, "thread") {
		t.Fatal("unstable or leaking event ID")
	}
	for _, raw := range []string{`{}`, `null`, `{"hook_event_name":"SubagentStop","session_id":"thread","turn_id":"turn"}`, `{"hook_event_name":"Stop","session_id":"thread"}`, `[]`, `{"session_id":32}`, strings.Repeat("x", 262145)} {
		if _, ok := codexEvent([]byte(raw), false); ok {
			t.Fatal("accepted invalid input")
		}
	}
}
func TestPrivateStoreNoOverwrite(t *testing.T) {
	s := fixtureStore(t)
	c := fixtureCredential()
	if e := s.saveNew("phone1", c); e != nil {
		t.Fatal(e)
	}
	if e := s.saveNew("phone1", c); e == nil {
		t.Fatal("overwrote existing config")
	}
	if got, e := s.load("phone1"); e != nil || got != c {
		t.Fatal(e, got)
	}
	if e := s.saveNew("phone2", c); e != nil {
		t.Fatal(e)
	}
	if _, e := s.path("../escape"); e == nil {
		t.Fatal("accepted traversal")
	}
}
func TestLockExclusion(t *testing.T) {
	s := fixtureStore(t)
	unlock, e := s.lock("phone")
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	if _, e := s.lock("phone"); e == nil {
		t.Fatal("lock not exclusive")
	}
}
func TestPairInputAndExistingProfile(t *testing.T) {
	s := fixtureStore(t)
	var calls atomic.Int32
	r := fixtureRelay(t, func(w http.ResponseWriter, q *http.Request) {
		calls.Add(1)
		if q.URL.Path != "/production/v1/pair/exchange" || q.Header.Get("Authorization") != "" {
			t.Error("wrong pairing route/auth")
		}
		json.NewEncoder(w).Encode(map[string]string{"hostToken": strings.Repeat("A", 43), "hostId": "host-one"})
	})
	if e := s.pair("phone", "production", "host-one", strings.Repeat("B", 43), r); e != nil {
		t.Fatal(e)
	}
	if e := s.pair("phone", "production", "host-one", strings.Repeat("B", 43), r); e == nil {
		t.Fatal("overwrote profile")
	}
	if calls.Load() != 1 {
		t.Fatal("unexpected second exchange")
	}
	if _, e := os.Stat(filepath.Join(s.dir, "phone.pending")); !os.IsNotExist(e) {
		t.Fatal("marker not cleaned")
	}
}
func TestPairAmbiguousResultNeverRetries(t *testing.T) {
	for _, body := range []string{`not json`, `{"hostToken":"bad","hostId":"host-one"}`, `{"hostToken":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","hostId":"wrong-host"}`} {
		t.Run(body, func(t *testing.T) {
			s := fixtureStore(t)
			var calls atomic.Int32
			r := fixtureRelay(t, func(w http.ResponseWriter, q *http.Request) { calls.Add(1); io.WriteString(w, body) })
			for i := 0; i < 2; i++ {
				if e := s.pair("phone", "production", "host-one", strings.Repeat("B", 43), r); e == nil {
					t.Fatal("accepted bad pairing")
				}
			}
			if calls.Load() != 1 {
				t.Fatal("retried ambiguous exchange")
			}
			if _, e := s.load("phone"); e == nil {
				t.Fatal("invalid credential persisted")
			}
		})
	}
}
func TestSendMinimalPayload(t *testing.T) {
	var count int
	r := fixtureRelay(t, func(w http.ResponseWriter, q *http.Request) {
		count++
		if q.URL.Path != "/production/v1/events" || q.Header.Get("Authorization") != "Bearer "+strings.Repeat("A", 43) {
			t.Error("wrong route/auth")
		}
		var body map[string]any
		json.NewDecoder(q.Body).Decode(&body)
		if len(body) != 2 || body["eventId"] != "one" || body["status"] != "attention" {
			t.Error("unexpected data", body)
		}
		io.WriteString(w, `{"accepted":true}`)
	})
	if e := r.send(context.Background(), fixtureCredential(), event{"one", "attention"}); e != nil {
		t.Fatal(e)
	}
	if count != 1 {
		t.Fatal(count)
	}
}
func TestRelayRejectsResponsesAndRedirects(t *testing.T) {
	for _, kind := range []string{"redirect", "oversize", "invalid", "denied", "notaccepted"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			r := fixtureRelay(t, func(w http.ResponseWriter, q *http.Request) {
				calls++
				switch kind {
				case "redirect":
					w.Header().Set("Location", "/leak")
					w.WriteHeader(302)
				case "oversize":
					io.WriteString(w, strings.Repeat(" ", 8193))
				case "invalid":
					io.WriteString(w, "secret response")
				case "denied":
					w.WriteHeader(401)
					io.WriteString(w, "token secret")
				default:
					io.WriteString(w, `{"accepted":false}`)
				}
			})
			e := r.send(context.Background(), fixtureCredential(), event{"one", "completed"})
			if e == nil || strings.Contains(e.Error(), "secret") {
				t.Fatal("unsafe response handling", e)
			}
			if calls != 1 {
				t.Fatal("retried/followed redirect")
			}
		})
	}
}
func TestNetworkBound(t *testing.T) {
	// Explicit release also lets httptest.Close finish if the server has not
	// observed the client's cancelled connection yet.
	release := make(chan struct{})
	r := fixtureRelay(t, func(w http.ResponseWriter, q *http.Request) {
		select {
		case <-q.Context().Done():
		case <-release:
		}
	})
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if e := r.send(ctx, fixtureCredential(), event{"one", "completed"}); e == nil {
		t.Fatal("no timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("deadline exceeded")
	}
}
func TestHookDoesNotAffectTask(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	for _, raw := range []string{`invalid`, `{"hook_event_name":"Stop","session_id":"a","turn_id":"b"}`} {
		var out, errOut bytes.Buffer
		if code := run([]string{"codex-hook", "missing"}, strings.NewReader(raw), &out, &errOut, newRelay()); code != 0 || out.String() != "{}\n" || errOut.Len() != 0 {
			t.Fatal(code, out.String(), errOut.String())
		}
	}
}
