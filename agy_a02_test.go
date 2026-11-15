package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"net.potafree/shinphony/hook/internal/notifier"
)

// A02: the built production binary, invoked through its real `agy-hook`
// dispatch, sends events over the private IPC to the production serve() and
// deliver() functions. Only the HTTP client the daemon already accepts as a
// parameter carries test trust for a loopback httptest TLS relay, so the real
// origin, auth header and TLS verification code run unchanged.
func productionBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "shinphony-hook")
	// Bounded: a stalled module fetch must fail the test, not hang the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out, ".")
	cmd.Env = os.Environ()
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, data)
	}
	return out
}

// managedCopy installs the production binary under the immutable name the hook
// entry accepts, exactly where the daemon keeps its socket.
func managedCopy(t *testing.T, binary, dir string) string {
	t.Helper()
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	dst := filepath.Join(dir, "shinphony-hook-"+hex.EncodeToString(sum[:]))
	if err := os.WriteFile(dst, data, 0700); err != nil {
		t.Fatal(err)
	}
	return dst
}

type a02Relay struct {
	mu      sync.Mutex
	paths   []string
	auth    []string
	bodies  []map[string]any
	seen    chan struct{}
	handler http.Handler
}

func newA02Relay() (*a02Relay, *httptest.Server) {
	r := &a02Relay{seen: make(chan struct{}, 1)}
	r.handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(req.Body, 16384))
		var parsed map[string]any
		if json.Unmarshal(body, &parsed) == nil {
			r.mu.Lock()
			r.paths = append(r.paths, req.URL.Path)
			r.auth = append(r.auth, req.Header.Get("Authorization"))
			r.bodies = append(r.bodies, parsed)
			r.mu.Unlock()
			select {
			case r.seen <- struct{}{}:
			default:
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"accepted":true}`)
	})
	return r, httptest.NewTLSServer(r.handler)
}

func (r *a02Relay) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

func (r *a02Relay) snapshot() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]map[string]any{}, r.bodies...)
}

// testClient dials the loopback relay while keeping the production request URL
// (https://notify.potafree.net/...). Trust for the test certificate lives only
// in this client; nothing is installed globally.
func testClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	base, ok := srv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected httptest transport")
	}
	tr := base.Clone()
	tr.Proxy = nil
	// Verified TLS against the test certificate: its SAN is example.com. No
	// InsecureSkipVerify, and the production URL keeps notify.potafree.net.
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func runHook(t *testing.T, binary, event, payload string) string {
	t.Helper()
	cmd := exec.Command(binary, "agy-hook", event)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	cmd.Stdin = strings.NewReader(payload)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", event, err, out.String())
	}
	return strings.TrimSpace(out.String())
}

func TestAgyProductionBinaryToRelay(t *testing.T) {
	// Build first: the build needs the real module cache, while the hook and
	// daemon below must run with an isolated HOME.
	binary := productionBinary(t)
	home := privateTemp(t)
	t.Setenv("HOME", home)
	dir := filepath.Join(home, "state")
	creds := filepath.Join(home, "credentials")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	managed := managedCopy(t, binary, dir)

	// Pairing is written by the real store with an injected transport; nothing
	// contacts a relay.
	manager := notifier.Manager{Directory: creds, Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"hostId":"host","hostToken":"` + strings.Repeat("a", 43) + `"}`))}, nil
	})}
	if err := manager.Pair("phone", "sandbox", "host", strings.Repeat("b", 43)); err != nil {
		t.Fatal(err)
	}

	relay, srv := newA02Relay()
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, dir, deliver(creds, testClient(t, srv)), creds) }()
	defer func() { cancel(); <-done }()

	socket := filepath.Join(dir, "state.db") // the daemon creates the queue here
	_ = socket
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.Command(managed, "--state-dir", dir, "--credentials-dir", creds, "status")
		cmd.Env = append(os.Environ(), "HOME="+home)
		if out, err := cmd.Output(); err == nil && strings.Contains(string(out), `"service":"running"`) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	const session = "a02c0e1e-0000-4000-8000-000000000002"
	base := `"conversationId":"` + session + `","workspacePaths":["/src/hook-a02"]`
	steps := []struct{ event, payload, out, category, status string }{
		{"SessionStart", `{` + base + `,"lastUserInput":"fix the failing tests"}`, `{}`, "session_started", "completed"},
		{"PreInvocation", `{` + base + `,"invocationNum":0,"initialNumSteps":0,"lastUserInput":"fix the failing tests !n"}`, `{}`, "task_started", "completed"},
		{"PreToolUse", `{` + base + `,"stepIdx":2,"toolCall":{"name":"ask_question","args":{"questions":[{"question":"Which environment?","options":["staging","local"]}]}}}`, `{"decision":"allow"}`, "question", "attention"},
		{"PostToolUse", `{` + base + `,"stepIdx":2,"toolCall":{"name":"ask_question","args":{}}}`, `{}`, "task_started", "completed"},
		{"Stop", `{` + base + `,"executionNum":1,"terminationReason":"model_stop","error":"","fullyIdle":true}`, `{"decision":"allow"}`, "task_complete", "completed"},
		{"PreInvocation", `{` + base + `,"invocationNum":1,"initialNumSteps":4,"lastUserInput":"now run the deploy"}`, `{}`, "task_started", "completed"},
		{"Stop", `{` + base + `,"executionNum":2,"terminationReason":"error","error":"exit status 1","fullyIdle":true}`, `{"decision":"allow"}`, "error", "failed"},
	}
	want := sessionKey("agy", session)
	for i, s := range steps {
		if out := runHook(t, managed, s.event, s.payload); out != s.out {
			t.Fatalf("%s stdout = %q, want %q", s.event, out, s.out)
		}
		// Wait for exactly this step's delivery, so ordering is deterministic.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) && relay.count() < i+1 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && relay.count() < len(steps) {
		time.Sleep(50 * time.Millisecond)
	}
	bodies := relay.snapshot()
	if len(bodies) != len(steps) {
		t.Fatalf("relay received %d events, want %d: %+v", len(bodies), len(steps), bodies)
	}
	for i, body := range bodies {
		if body["category"] != steps[i].category || body["status"] != steps[i].status ||
			body["agent"] != "agy" || body["session"] != want {
			t.Fatalf("event %d = %+v, want %s/%s/agy/%s", i, body, steps[i].category, steps[i].status, want)
		}
		if id, _ := body["eventId"].(string); !identifier.MatchString(id) {
			t.Fatalf("event %d has no stable id: %+v", i, body)
		}
	}

	// Production auth travels unchanged: the stored host token.
	relay.mu.Lock()
	for _, auth := range relay.auth {
		if !strings.HasPrefix(auth, "Bearer ") {
			relay.mu.Unlock()
			t.Fatal("relay request without the host token")
		}
	}
	paths := append([]string{}, relay.paths...)
	relay.mu.Unlock()
	for _, path := range paths {
		if path != "/v1/events" {
			t.Fatalf("unexpected relay path %s", path)
		}
	}

	// Replays are deduped by the stable event IDs, not by a second push.
	before := relay.count()
	runHook(t, managed, "Stop", steps[4].payload)
	runHook(t, managed, "PostToolUse", steps[3].payload)
	time.Sleep(500 * time.Millisecond)
	if after := relay.count(); after != before {
		t.Fatalf("replays reached the relay: %d -> %d", before, after)
	}
}