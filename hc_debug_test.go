package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// agentGone makes the fake terminal look like a terminal whose program pid is
// no longer an ancestor of the reporting agent: a keep restart or an exit.
func agentGone(f *fakeHc) {
	f.mu.Lock()
	f.terminal.PID = os.Getpid() + 100000
	f.mu.Unlock()
}

// P2-1: the terminal is the same, the agent is gone. resolve-event must return a
// terminal-only route, attach-event and presence must stay strict.
func TestHcResolveTerminalOnlyWhenAgentIsGone(t *testing.T) {
	socket, f := fakeHcCore(t)
	f.mu.Lock()
	f.terminal.Parent = "t2"
	f.terminal.Labels = map[string]any{"where": "Shinphony / 1"}
	f.extra = map[string]hcTerminal{"t2": {Address: "t2", State: "live", CreatedMS: 456, PID: os.Getpid(),
		Labels: map[string]any{"where": "Shinphony / 1"}, Status: map[string]any{"app": "claude-code"}}}
	f.mu.Unlock()
	c := captureFakeHc(t, socket)
	agentGone(f)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if e := validateHcContext(ctx, c); e == nil {
		t.Fatal("strict validation accepted a dead agent")
	}
	if e := hcTerminalOnlyRoute(ctx, c); e != nil {
		t.Fatal("terminal-only route rejected the same terminal", e)
	}
	out, e := resolveHcEvent(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	if !out.TerminalOnly || out.Route != "" || out.Binary != "" {
		t.Fatalf("not a terminal-only route: %+v", out.taskContext)
	}
	// The identity and the conversation survive, so the app can open the parent.
	if out.Hc.Address != "t1" || out.Hc.CreatedMS != c.Hc.CreatedMS || out.Hc.Parent != "t2" ||
		out.ParentTitle != "Claude Code — Shinphony" || out.Space != "Shinphony" {
		t.Fatalf("terminal-only identity or conversation lost: %+v %+v", out.Hc, out.taskContext)
	}
	// The stored snapshot must not be mutated: the daemon keeps its event route.
	if c.Route != "event-a" || c.Binary != strings.Repeat("a", 64) || c.TerminalOnly {
		t.Fatalf("stored snapshot mutated: %+v", c)
	}
	raw, e := json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{`"terminalOnly":true`, `"route":""`, `"binary":""`, `"parentTitle":"Claude Code — Shinphony"`, `"socket":`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("reply missing %s: %s", want, raw)
		}
	}
	// Without the marker an old client keeps its current behaviour: no route match.
	var reply map[string]any
	if json.Unmarshal(raw, &reply) != nil || reply["route"] == "event-a" {
		t.Fatal("terminal-only reply still matches the event route")
	}
}

// The strict paths are unchanged: a live agent keeps the event route, a
// recreated terminal is rejected everywhere.
func TestHcResolveStrictAndRecreated(t *testing.T) {
	socket, f := fakeHcCore(t)
	c := captureFakeHc(t, socket)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, e := resolveHcEvent(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	if out.TerminalOnly || out.Route != "event-a" || out.Binary != strings.Repeat("a", 64) {
		t.Fatalf("live agent lost its event route: %+v", out.taskContext)
	}
	// A new created_ms is a different terminal, not a terminal-only route.
	f.mu.Lock()
	f.terminal.CreatedMS++
	f.mu.Unlock()
	if e := hcTerminalOnlyRoute(ctx, c); e == nil {
		t.Fatal("recreated terminal accepted as terminal-only")
	}
	if _, e := resolveHcEvent(ctx, c); e == nil {
		t.Fatal("recreated terminal resolved")
	}
	f.mu.Lock()
	f.terminal.CreatedMS = 123
	f.terminal.State = "finished"
	f.mu.Unlock()
	if e := hcTerminalOnlyRoute(ctx, c); e == nil {
		t.Fatal("finished terminal accepted as terminal-only")
	}
	// attach-event keeps the strict check and never runs a command.
	f.mu.Lock()
	f.terminal.State = "live"
	f.mu.Unlock()
	agentGone(f)
	if e := attachHcContext(ctx, &out); e == nil {
		t.Fatal("attach-event accepted a dead agent")
	}
	// A tmux snapshot is untouched by the hc rule.
	tmux := &localSnapshot{taskContext: taskContext{Multiplexer: "tmux", Route: "event-a"}}
	if same, e := resolveHcEvent(ctx, tmux); e != nil || same.Route != "event-a" || same.TerminalOnly {
		t.Fatalf("tmux resolve changed: %+v", same.taskContext)
	}
	if _, e := resolveHcEvent(ctx, nil); e == nil {
		t.Fatal("nil snapshot resolved")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, method := range f.calls {
		if method != "hello" && method != "terminal.get" {
			t.Fatal("unexpected side effect", method)
		}
	}
}

// P2-2: the dry run prints the snapshot, the projection and both payloads, and
// touches nothing but the read-only core query.
func TestDebugHcCapturePrintsPayloads(t *testing.T) {
	socket, f := fakeHcCore(t)
	f.mu.Lock()
	f.terminal.Name = "pi-ghostty-s6"
	f.terminal.Labels = map[string]any{"where": "Shinphony / 1"}
	f.terminal.Status = map[string]any{"app": "pi", "state": "done"}
	f.terminal.Parent = "t2"
	f.extra = map[string]hcTerminal{"t2": {Address: "t2", State: "live", CreatedMS: 456, PID: os.Getpid(),
		Labels: map[string]any{"where": "Shinphony / 1"}, Status: map[string]any{"app": "claude-code"}}}
	f.mu.Unlock()
	getenv := func(key string) string {
		if key == "HC_SOCKET" {
			return socket
		}
		return ""
	}
	var out bytes.Buffer
	if e := debugHcCaptureWith(&out, "t1", "completed", getenv, t.TempDir(), 1800000000); e != nil {
		t.Fatal(e)
	}
	var report hcDebugReport
	if e := json.Unmarshal(out.Bytes(), &report); e != nil {
		t.Fatal(e, out.String())
	}
	if report.Address != "t1" || report.Session != "default" || report.Status != "completed" || report.Socket != socket {
		t.Fatalf("report header: %+v", report)
	}
	if report.Snapshot == nil || report.Snapshot.Hc == nil {
		t.Fatal("no snapshot")
	}
	if report.Snapshot.Hc.Parent != "t2" || report.Snapshot.Hc.ParentTitle != "Claude Code — Shinphony" || report.Snapshot.Space != "Shinphony" {
		t.Fatalf("snapshot: %+v %+v", report.Snapshot.Hc, report.Snapshot.taskContext)
	}
	// A dry run has no agent, so no agent start time either.
	if report.Snapshot.AgentPID != 0 || report.Snapshot.AgentStart != "" {
		t.Fatalf("dry run claimed an agent: %+v", report.Snapshot)
	}
	if report.Context.ParentTitle != "Claude Code — Shinphony" || report.Context.Session != "pi-ghostty-s6" {
		t.Fatalf("context: %+v", report.Context)
	}
	aps := report.APNs["aps"].(map[string]any)
	alert := aps["alert"].(map[string]any)
	if alert["title"] != "Claude Code — Shinphony" || alert["subtitle"] != "pi-ghostty-s6 · Done" || alert["body"] != "Task completed" {
		t.Fatalf("alert: %+v", alert)
	}
	if aps["thread-id"] != "debug:debug" {
		t.Fatalf("thread id: %v", aps["thread-id"])
	}
	if report.LiveActivity["conversation"] != "Claude Code — Shinphony" || report.LiveActivity["helper"] != "pi-ghostty-s6" ||
		report.LiveActivity["status"] != "completed" || report.LiveActivity["project"] != "pi-ghostty-s6" {
		t.Fatalf("live activity: %+v", report.LiveActivity)
	}
	if json.Valid([]byte(report.LiveActivity["contextJSON"].(string))) == false {
		t.Fatal("activity context is not JSON")
	}
	if len(report.Notes) < 3 {
		t.Fatalf("notes: %v", report.Notes)
	}
	// Nothing was written: only the two read methods reached the core.
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, method := range f.calls {
		if method != "hello" && method != "terminal.get" {
			t.Fatal("unexpected side effect", method)
		}
	}
}

func TestDebugHcCaptureWithoutParentAndAttention(t *testing.T) {
	socket, f := fakeHcCore(t)
	f.mu.Lock()
	f.terminal.Name = "pi-plain"
	f.mu.Unlock()
	getenv := func(key string) string {
		if key == "HC_SOCKET" {
			return socket
		}
		return ""
	}
	var out bytes.Buffer
	if e := debugHcCaptureWith(&out, "t1", "attention", getenv, t.TempDir(), 1); e != nil {
		t.Fatal(e)
	}
	var report hcDebugReport
	if e := json.Unmarshal(out.Bytes(), &report); e != nil {
		t.Fatal(e)
	}
	alert := report.APNs["aps"].(map[string]any)["alert"].(map[string]any)
	if alert["title"] != "pi-plain · Codex" || alert["subtitle"] != report.Context.Title || alert["body"] != "Task needs your attention" {
		t.Fatalf("alert without parent: %+v", alert)
	}
	if _, ok := report.LiveActivity["helper"]; ok {
		t.Fatal("helper present without a parent")
	}
	if report.LiveActivity["conversation"] != report.Context.Title {
		t.Fatalf("conversation without parent: %v", report.LiveActivity["conversation"])
	}
}

func TestDebugHcCaptureRejectsBadInput(t *testing.T) {
	none := func(string) string { return "" }
	for name, tc := range map[string]struct {
		address, status string
		getenv          func(string) string
		want            string
	}{
		"address": {"../../etc", "completed", none, "invalid_hc_address"},
		"status":  {"t1", "running", none, "invalid_status"},
		"no core": {"t1", "completed", none, "no_local_hc_core"},
		"bad session": {"t1", "completed", func(k string) string {
			if k == "HC_SESSION" {
				return "../x"
			}
			return ""
		}, "no_local_hc_core"},
		"bad socket": {"t1", "completed", func(k string) string {
			if k == "HC_SOCKET" {
				return "relative"
			}
			return ""
		}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			e := debugHcCaptureWith(&out, tc.address, tc.status, tc.getenv, t.TempDir(), 1)
			if e == nil {
				if tc.want != "" {
					t.Fatalf("accepted %+v", tc)
				}
				return
			}
			if tc.want != "" && e.Error() != tc.want {
				t.Fatalf("error %q, want %q", e, tc.want)
			}
			if out.Len() != 0 {
				t.Fatal("printed a report on failure")
			}
		})
	}
}

// The endpoint comes from the state lock herdr itself writes; a stale lock is
// skipped rather than dialled.
func TestHcDebugEndpointDiscovery(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "state", "herdr-core", "default")
	if e := os.MkdirAll(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(home, "core.sock")
	if e := os.WriteFile(socket, nil, 0o600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "core.lock"), []byte(socket+"\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	env := map[string]string{"XDG_STATE_HOME": filepath.Join(home, "state")}
	getenv := func(k string) string { return env[k] }
	if got, session := hcDebugEndpoint(getenv, home); got != socket || session != "default" {
		t.Fatalf("endpoint %q/%q", got, session)
	}
	// Named session, socket in the state dir.
	named := filepath.Join(home, "state", "herdr-core", "work")
	if e := os.MkdirAll(named, 0o700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(named, "work.sock"), nil, 0o600); e != nil {
		t.Fatal(e)
	}
	env["HC_SESSION"] = "work"
	if got, session := hcDebugEndpoint(getenv, home); got != filepath.Join(named, "work.sock") || session != "work" {
		t.Fatalf("named endpoint %q/%q", got, session)
	}
	// An explicit HC_SOCKET wins and a stale lock is not dialled.
	env["HC_SESSION"] = "default"
	env["HC_SOCKET"] = socket
	if got, _ := hcDebugEndpoint(getenv, home); got != socket {
		t.Fatalf("explicit endpoint %q", got)
	}
	delete(env, "HC_SOCKET")
	if e := os.Remove(socket); e != nil {
		t.Fatal(e)
	}
	if got, _ := hcDebugEndpoint(getenv, home); got != "" {
		t.Fatalf("stale lock used: %q", got)
	}
	if got, _ := hcDebugEndpoint(func(string) string { return "" }, home); got != "" {
		t.Fatalf("empty home resolved %q", got)
	}
}
