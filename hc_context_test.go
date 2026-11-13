package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeHc struct {
	mu         sync.Mutex
	core       string
	terminal   hcTerminal
	extra      map[string]hcTerminal
	silent     map[string]bool
	raw        string
	generation int
	calls      []string
}

// lookup returns the row for an address. The primary terminal answers to its
// own address; extra holds parents and other rows of the same fake core.
func (f *fakeHc) lookup(address string) (hcTerminal, bool) {
	if address == f.terminal.Address {
		return f.terminal, true
	}
	t, ok := f.extra[address]
	return t, ok
}

func fakeHcCore(t *testing.T) (string, *fakeHc) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket fixture")
	}
	dir, e := os.MkdirTemp("/tmp", "hc-hook-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "c.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeHc{core: "core-a", generation: 1, extra: map[string]hcTerminal{}, silent: map[string]bool{},
		terminal: hcTerminal{Address: "t1", Name: "中文 project", State: "live", CreatedMS: 123, PID: os.Getpid()}}
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				scanner := bufio.NewScanner(conn)
				for scanner.Scan() {
					var req struct {
						ID     int             `json:"id"`
						Method string          `json:"method"`
						Params json.RawMessage `json:"params"`
					}
					if json.Unmarshal(scanner.Bytes(), &req) != nil {
						return
					}
					f.mu.Lock()
					f.calls = append(f.calls, req.Method)
					raw := f.raw
					silent := false
					var result any
					switch req.Method {
					case "hello":
						result = map[string]any{"generation": f.generation, "core": map[string]string{"id": f.core}, "methods": []string{"terminal.get", "terminal.attach"}, "new_field": true}
					case "terminal.get":
						var p struct {
							Terminal string `json:"terminal"`
						}
						json.Unmarshal(req.Params, &p)
						silent = f.silent[p.Terminal]
						if t, ok := f.lookup(p.Terminal); ok {
							result = t
						}
					}
					f.mu.Unlock()
					if silent {
						continue // a wedged core: never answer, let the client deadline win
					}
					if raw != "" {
						conn.Write([]byte(raw))
						return
					}
					if result == nil {
						json.NewEncoder(conn).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32000, "message": "unknown_terminal"}})
						continue
					}
					json.NewEncoder(conn).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
				}
			}()
		}
	}()
	return socket, f
}
func captureFakeHc(t *testing.T, socket string) *localSnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := captureHcContext(ctx, &hookSource{Agent: "codex", Thread: "thread-a", ParentPID: os.Getpid(), HcAddress: "t1", HcSocket: socket}, "event-a", strings.Repeat("a", 64))
	if c == nil {
		t.Fatal("missing hc capture")
	}
	return c
}

// captureFakeHcWithin is captureFakeHc with a caller-chosen budget, used to
// prove a wedged parent read cannot outlive the capture deadline.
func captureFakeHcWithin(t *testing.T, socket string, budget time.Duration) (*localSnapshot, time.Duration) {
	t.Helper()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	c := captureHcContext(ctx, &hookSource{Agent: "codex", Thread: "thread-a", ParentPID: os.Getpid(), HcAddress: "t1", HcSocket: socket}, "event-a", strings.Repeat("a", 64))
	return c, time.Since(start)
}

// A helper's conversation comes from the parent's own row, titled the way the
// app titles an hc tab.
func TestHcCaptureParentConversation(t *testing.T) {
	socket, f := fakeHcCore(t)
	f.mu.Lock()
	f.terminal.Name = "pi-ghostty-s6"
	f.terminal.Labels = map[string]any{"where": "Shinphony / 1"}
	f.terminal.Status = map[string]any{"app": "pi", "state": "done"}
	f.terminal.Parent = "t2"
	f.extra = map[string]hcTerminal{"t2": {Address: "t2", State: "live", CreatedMS: 456, PID: os.Getpid(),
		Labels: map[string]any{"where": "Shinphony / 1"}, Status: map[string]any{"app": "claude-code", "state": "done"},
		Foreground: map[string]any{"argv": []any{"claude", "--resume"}, "cwd": "/Volumes/ZT/repos/Shinphony", "name": "2.1.321"}}}
	f.mu.Unlock()
	c := captureFakeHc(t, socket)
	if c.Hc.Parent != "t2" || c.Hc.ParentTitle != "Claude Code — Shinphony" || c.Hc.Space != "Shinphony" {
		t.Fatal("parent identity", c.Hc)
	}
	// The conversation reaches the network projection as plain display text.
	if c.Parent != "t2" || c.ParentTitle != "Claude Code — Shinphony" || c.Space != "Shinphony" {
		t.Fatal("parent projection", c.taskContext)
	}
	// The helper keeps its own terminal label for the subtitle.
	if c.Session != "pi-ghostty-s6" {
		t.Fatal("helper label", c.Session)
	}
	if e := validateHcContext(context.Background(), c); e != nil {
		t.Fatal(e)
	}
}

// The app's title order: name, then app + space, then program + folder, then the
// address.
func TestHcTitleRules(t *testing.T) {
	where := map[string]any{"where": "repos / deep / 2"}
	for name, tc := range map[string]struct {
		terminal hcTerminal
		want     string
		space    string
	}{
		"name wins":             {hcTerminal{Name: "pi-ghostty-s6", Address: "t1", Labels: where, Status: map[string]any{"app": "claude-code"}}, "pi-ghostty-s6", "repos / deep"},
		"app and space":         {hcTerminal{Address: "t1", Labels: where, Status: map[string]any{"app": "claude-code"}}, "Claude Code — repos / deep", "repos / deep"},
		"claude label":          {hcTerminal{Address: "t1", Labels: map[string]any{"where": "Shinphony / 1"}, Status: map[string]any{"app": "claude"}}, "Claude Code — Shinphony", "Shinphony"},
		"app without space":     {hcTerminal{Address: "t1", Status: map[string]any{"app": "pi"}}, "pi", ""},
		"program and folder":    {hcTerminal{Address: "t1", Foreground: map[string]any{"argv": []any{"/opt/homebrew/bin/zsh"}, "cwd": "/Volumes/ZT/repos/Shinphony"}}, "zsh · Shinphony", ""},
		"program name fallback": {hcTerminal{Address: "t1", Cwd: "/tmp", Foreground: map[string]any{"name": "node"}}, "node · tmp", ""},
		"folder only":           {hcTerminal{Address: "t1", Cwd: `C:\Users\pi\work`}, "work", ""},
		"address":               {hcTerminal{Address: "t1"}, "t1", ""},
	} {
		if got := hcTitle(tc.terminal); got != tc.want {
			t.Fatalf("%s: title %q, want %q", name, got, tc.want)
		}
		if got := hcSpace(tc.terminal); got != tc.space {
			t.Fatalf("%s: space %q, want %q", name, got, tc.space)
		}
	}
}

// A missing parent, a cycle and a dead ancestor all leave the event intact.
func TestHcParentMissingCycleAndCap(t *testing.T) {
	live := func(address, parent, name string) hcTerminal {
		return hcTerminal{Address: address, Parent: parent, Name: name, State: "live", CreatedMS: 100, PID: os.Getpid()}
	}
	for name, tc := range map[string]struct {
		parent   string
		extra    map[string]hcTerminal
		wantAddr string
		wantName string
	}{
		"missing parent": {parent: "t9", wantAddr: "", wantName: ""},
		"cycle": {parent: "t2", wantAddr: "t2", wantName: "conv-2",
			extra: map[string]hcTerminal{"t2": live("t2", "t1", "conv-2")}},
		"self cycle": {parent: "t1", wantAddr: "", wantName: ""},
		"three hops": {parent: "t2", wantAddr: "t4", wantName: "conv-4", extra: map[string]hcTerminal{
			"t2": live("t2", "t3", "conv-2"), "t3": live("t3", "t4", "conv-3"), "t4": live("t4", "t5", "conv-4"), "t5": live("t5", "", "conv-5")}},
		"dead ancestor": {parent: "t2", wantAddr: "", wantName: "", extra: map[string]hcTerminal{
			"t2": {Address: "t2", Name: "conv-2", State: "finished", CreatedMS: 100, PID: os.Getpid()}}},
	} {
		t.Run(name, func(t *testing.T) {
			socket, f := fakeHcCore(t)
			f.mu.Lock()
			f.terminal.Parent = tc.parent
			f.extra = tc.extra
			f.mu.Unlock()
			c := captureFakeHc(t, socket)
			if c.Hc.Parent != tc.wantAddr || c.Hc.ParentTitle != tc.wantName {
				t.Fatalf("parent %q/%q, want %q/%q", c.Hc.Parent, c.Hc.ParentTitle, tc.wantAddr, tc.wantName)
			}
			if c.Parent != tc.wantAddr || c.ParentTitle != tc.wantName {
				t.Fatalf("projection %q/%q", c.Parent, c.ParentTitle)
			}
		})
	}
}

// A parent that never answers costs the capture budget, not the event.
func TestHcParentReadStaysWithinBudget(t *testing.T) {
	socket, f := fakeHcCore(t)
	f.mu.Lock()
	f.terminal.Parent = "t2"
	f.silent = map[string]bool{"t2": true}
	f.mu.Unlock()
	c, elapsed := captureFakeHcWithin(t, socket, 600*time.Millisecond)
	if c == nil {
		t.Fatal("wedged parent lost the event")
	}
	if c.Hc.Parent != "" || c.ParentTitle != "" {
		t.Fatal("unexpected parent", c.Hc)
	}
	if elapsed > 1200*time.Millisecond {
		t.Fatalf("capture took %s, beyond the production 1.2s budget", elapsed)
	}
}
func TestHcCaptureValidateProjectionAndReplacement(t *testing.T) {
	socket, f := fakeHcCore(t)
	c := captureFakeHc(t, socket)
	if c.Multiplexer != "hc" || c.Session != "中文 project" || c.Window != "t1" || c.Preview != "" {
		t.Fatal(c)
	}
	if e := validateHcContext(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(c.taskContext)
	for _, private := range []string{"socket", "coreId", "createdMs", "agentPid", "hcSocket"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private field leaked", string(raw))
		}
	}
	original := snapshotRouteKey(c)
	// A core restart reloads the same persisted registry: same terminal.
	f.mu.Lock()
	f.core = "core-b"
	f.mu.Unlock()
	if e := validateHcContext(context.Background(), c); e != nil {
		t.Fatal("core restart rejected", e)
	}
	// A kept terminal restarts its program under a new pid, same terminal.
	f.mu.Lock()
	f.terminal.PID = os.Getppid()
	f.mu.Unlock()
	if e := validateHcContext(context.Background(), c); e != nil {
		t.Fatal("kept-program restart rejected", e)
	}
	clone := *c
	target := *c.Hc
	clone.Hc = &target
	target.PID = os.Getppid()
	if snapshotRouteKey(&clone) != original {
		t.Fatal("pid change moved the route")
	}
	// A recreated terminal has a new created_ms and is a different terminal.
	f.mu.Lock()
	f.core = "core-a"
	f.terminal.PID = os.Getpid()
	f.terminal.CreatedMS++
	f.mu.Unlock()
	if validateHcContext(context.Background(), c) == nil {
		t.Fatal("recreated terminal accepted")
	}
	f.mu.Lock()
	f.terminal.CreatedMS = 123
	f.terminal.State = "finished"
	f.mu.Unlock()
	if validateHcContext(context.Background(), c) == nil {
		t.Fatal("finished terminal accepted")
	}
	f.mu.Lock()
	f.terminal.State = "live"
	f.mu.Unlock()
	reused := *c
	target = *c.Hc
	reused.Hc = &target
	target.CreatedMS++
	if snapshotRouteKey(&reused) == original {
		t.Fatal("address reuse shares route")
	}
	c.AgentStart = "replaced"
	if validateHcContext(context.Background(), c) == nil {
		t.Fatal("reused agent PID")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, method := range f.calls {
		if method != "hello" && method != "terminal.get" {
			t.Fatal("unexpected side effect", method)
		}
	}
}
func TestHcRPCRejectsMalformedResponses(t *testing.T) {
	for name, raw := range map[string]string{"bad-json": "x\n", "id-replay": `{"jsonrpc":"2.0","id":99,"result":{}}` + "\n", "utf8": "\xff\n", "truncated": "{", "oversize": strings.Repeat("x", 256*1024+1) + "\n"} {
		t.Run(name, func(t *testing.T) {
			socket, f := fakeHcCore(t)
			f.mu.Lock()
			f.raw = raw
			f.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			rpc, e := openHcRPC(ctx, socket)
			if e != nil {
				t.Fatal(e)
			}
			defer rpc.close()
			if _, e = rpc.hello(); e == nil {
				t.Fatal("malformed reply accepted")
			}
		})
	}
	socket, f := fakeHcCore(t)
	f.mu.Lock()
	f.generation = 2
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rpc, e := openHcRPC(ctx, socket)
	if e != nil {
		t.Fatal(e)
	}
	defer rpc.close()
	if _, e = rpc.hello(); e == nil {
		t.Fatal("unknown generation accepted")
	}
}
func TestHcSourceWinsAndDoesNotGuessMissingIdentity(t *testing.T) {
	env := map[string]string{"HC_TERMINAL_ID": "t1", "HC_TERMINAL_SOCKET": "/tmp/hc.sock", "TMUX": "/tmp/tmux,1,0", "TMUX_PANE": "%1"}
	get := func(k string) string { return env[k] }
	s := hookSourceFromEnv("codex", "thread", os.Getpid(), get)
	if multiplexer(get) != "hc" || s.HcAddress != "t1" || s.HcSocket != "/tmp/hc.sock" {
		t.Fatal(s)
	}
	if captureContext(context.Background(), &hookSource{Agent: "codex", Thread: "thread", HcAddress: "bad", Tmux: env["TMUX"], Pane: "%1"}, "event", "") != nil {
		t.Fatal("fell through to tmux")
	}
}
func TestHcPresenceExactTargetAndTTL(t *testing.T) {
	socket, _ := fakeHcCore(t)
	c := captureFakeHc(t, socket)
	q := testQueue(t)
	if e := q.saveContext(c, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	q.registerPresence(mux)
	request := func(body string) int {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("POST", "/v1/hc-presence", strings.NewReader(body)))
		return w.Code
	}
	if request(`{"profile":"phone","event":"event-a","active":true}`) != 200 {
		t.Fatal("lease rejected")
	}
	if !q.activelyViewing(context.Background(), "phone", c) {
		t.Fatal("lease missing")
	}
	body, _ := json.Marshal(map[string]any{"profile": "phone", "target": hcPresenceIdentity{CoreID: c.Hc.CoreID, Address: c.Hc.Address, CreatedMS: c.Hc.CreatedMS, PID: c.Hc.PID}, "active": true})
	if request(string(body)) != 200 {
		t.Fatal("identity-only foreground lease rejected")
	}
	invalid, _ := json.Marshal(map[string]any{"profile": "phone", "target": hcPresenceIdentity{CoreID: c.Hc.CoreID, Address: c.Hc.Address, CreatedMS: c.Hc.CreatedMS + 1, PID: c.Hc.PID}, "active": true})
	if request(string(invalid)) != 404 {
		t.Fatal("replacement identity acquired lease")
	}
	// A kept-program restart or a core restart is the same terminal: the pid and
	// core id from the app are diagnostics, not identity.
	restarted, _ := json.Marshal(map[string]any{"profile": "phone", "target": hcPresenceIdentity{CoreID: "core-b", Address: c.Hc.Address, CreatedMS: c.Hc.CreatedMS, PID: c.Hc.PID + 1}, "active": true})
	if request(string(restarted)) != 200 {
		t.Fatal("restarted terminal lost its lease")
	}

	other := *c
	target := *c.Hc
	target.CreatedMS++
	other.Hc = &target
	if q.activelyViewing(context.Background(), "phone", &other) {
		t.Fatal("suppressed another terminal")
	}
	q.db.Exec("UPDATE hc_presence SET expires=?", time.Now().Unix()-1)
	if q.activelyViewing(context.Background(), "phone", c) {
		t.Fatal("background TTL retained")
	}
	if request(`{"profile":"phone","event":"event-a","active":false}`) != 200 {
		t.Fatal("clear rejected")
	}
	if request(`{"profile":"phone","event":"missing","active":true}`) != 404 {
		t.Fatal("unknown target accepted")
	}
	if request(`{"profile":"phone","event":"event-a","active":true,"socket":"/tmp/guess"}`) != 400 {
		t.Fatal("caller socket accepted")
	}
}
