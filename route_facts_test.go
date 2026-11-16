package main

// Round 02 (review P2-1): every agent's hook invocation carries the same route
// facts a tap route uses, so the inventory joins a claude/dsh/agy event to its
// pane or terminal instead of guessing by project. Route facts are display/join
// data only: they never change a notification, its category or its text, and
// they never reach the relay.
import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"net.potafree/shinphony/hook/internal/notifier"
)

const (
	hcEnvSocket  = "/tmp/hc/default.sock"
	tmuxEnvValue = "/tmp/tmux-1000/default,42,1"
)

func hcRouteEnv() func(string) string {
	return env(map[string]string{"HC_TERMINAL_ID": "t7", "HC_TERMINAL_SOCKET": hcEnvSocket, "HC_SESSION": "default"})
}

func tmuxRouteEnv() func(string) string {
	return env(map[string]string{"TMUX": tmuxEnvValue, "TMUX_PANE": "%3"})
}

// Every agent's event carries the route facts; the event stays valid.
func TestRouteFactsForEveryAgent(t *testing.T) {
	for _, agent := range []string{"claude", "dsh", "codex", "agy"} {
		e := agentEvent{Agent: agent, Session: sessionKey(agent, "s"), Kind: "prompt", Mux: "hc", Project: "x"}
		attachRouteFacts(&e, "s", 4321, hcRouteEnv())
		if !e.valid() {
			t.Fatalf("%s: event invalid with route facts: %+v", agent, e)
		}
		s := e.Source
		if s == nil || s.Agent != agent || s.Thread != "s" || s.ParentPID != 4321 {
			t.Fatalf("%s: source identity: %+v", agent, s)
		}
		if s.HcAddress != "t7" || s.HcSocket != hcEnvSocket || s.HcSession != "default" {
			t.Fatalf("%s: hc route: %+v", agent, s)
		}
		// The route the inventory joins on is exactly the tap route's.
		if got := routeKeyFromEvent(e); got != "hc\x00default\x00t7" {
			t.Fatalf("%s: route key %q", agent, got)
		}
	}
}

func TestRouteFactsFromTmux(t *testing.T) {
	e := agentEvent{Agent: "claude", Session: sessionKey("claude", "s"), Kind: "prompt", Mux: "tmux"}
	attachRouteFacts(&e, "s", 4321, tmuxRouteEnv())
	if !e.valid() {
		t.Fatalf("event invalid: %+v", e)
	}
	if e.Source.Pane != "%3" || tmuxSocketFrom(e.Source.Tmux) != "/tmp/tmux-1000/default" {
		t.Fatalf("tmux route: %+v", e.Source)
	}
	// The event and an inventory row of the same server agree on what identifies
	// this conversation.
	rows := parseTmuxWindows([]byte(tmuxLineOn("/tmp/tmux-1000/default", "work", 1, "tests", "1763249990", "%3", "/tmp", "zsh")+"\n"), inventoryClock())
	if len(rows) != 1 || rows[0].routeKey() != routeKeyFromEvent(e) || rows[0].routeKey() != "tmux\x00/tmp/tmux-1000/default\x00%3" {
		t.Fatalf("route keys differ: %+v %q", rows, routeKeyFromEvent(e))
	}
	// The same pane id in another server is another conversation.
	if other := parseTmuxWindows([]byte(tmuxLine("work", 1, "tests", "1763249990", "%3", "/tmp", "zsh")+"\n"), inventoryClock()); other[0].routeKey() == routeKeyFromEvent(e) {
		t.Fatal("pane ids from different servers collided")
	}
}

// Route facts are bounded and cleaned, and a malformed one costs the inventory a
// match, never the user a notification.
func TestRouteFactsAreBounded(t *testing.T) {
	e := agentEvent{Agent: "claude", Session: sessionKey("claude", "s"), Kind: "prompt", Mux: "hc"}
	attachRouteFacts(&e, "s", 4321, env(map[string]string{
		"HC_TERMINAL_ID":     "t 7\n",
		"HC_TERMINAL_SOCKET": "relative/path",
		"HC_SESSION":         "../escape",
		"TMUX":               "not,a,tmux,path",
		"TMUX_PANE":          "3",
	}))
	if !e.valid() {
		t.Fatalf("a bad route must not drop the event: %+v", e)
	}
	s := e.Source
	if s.HcAddress != "" || s.HcSocket != "" || s.HcSession != "" || s.Pane != "" || tmuxSocketFrom(s.Tmux) != "" {
		t.Fatalf("bad route facts survived: %+v", s)
	}
	if s.Agent != "claude" || s.Thread != "s" {
		t.Fatalf("identity lost: %+v", s)
	}
	// A route that is too long is dropped too.
	long := "/tmp/" + strings.Repeat("a", 1100)
	e = agentEvent{Agent: "claude", Session: sessionKey("claude", "s"), Kind: "prompt"}
	attachRouteFacts(&e, "s", 4321, env(map[string]string{"HC_TERMINAL_SOCKET": long}))
	if e.Source.HcSocket != "" {
		t.Fatal("an over-long socket survived")
	}
}

// Outside a multiplexer the event is still valid and still carries its identity,
// so the inventory keeps the unique-project fallback for it.
func TestRouteFactsOutsideAMultiplexer(t *testing.T) {
	e := agentEvent{Agent: "dsh", Session: sessionKey("dsh", "s"), Kind: "prompt", Project: "x"}
	attachRouteFacts(&e, "s", 4321, env(nil))
	if !e.valid() || e.Source == nil || routeKeyFromEvent(e) != "" {
		t.Fatalf("%+v", e)
	}
}

// The daemon accepts route facts from every agent, and keeps rejecting a source
// that does not identify the same session.
func TestAgentEventRouteValidation(t *testing.T) {
	base := agentEvent{Agent: "claude", Session: sessionKey("claude", "s"), Kind: "prompt", Mux: "hc"}
	good := base
	attachRouteFacts(&good, "s", 4321, hcRouteEnv())
	if !good.valid() {
		t.Fatal("a claude source must be accepted")
	}
	for _, tc := range []struct {
		name string
		edit func(*agentEvent)
	}{
		{"other agent", func(e *agentEvent) { e.Source.Agent = "codex" }},
		{"other thread", func(e *agentEvent) { e.Source.Thread = "other" }},
		{"no pid", func(e *agentEvent) { e.Source.ParentPID = 0 }},
	} {
		e := good
		cp := *good.Source
		e.Source = &cp
		tc.edit(&e)
		if e.valid() {
			t.Fatalf("%s: accepted", tc.name)
		}
	}
}

// Route facts are local join data: the relay payload carries none of them.
func TestRouteFactsDoNotReachTheRelay(t *testing.T) {
	e := agentEvent{Agent: "claude", Session: sessionKey("claude", "s"), Kind: "prompt", Body: "npm test", Mux: "tmux"}
	attachRouteFacts(&e, "s", 4321, hcRouteEnv())
	d := newTracker().decide(e, settings{TurnCompletePush: "all", RateLimitPerMinute: 600}, time.Unix(1800000000, 0))
	raw, err := json.Marshal(d.Details)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"t7", hcEnvSocket, "default", "%3", "4321"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("relay payload leaks %q: %s", leak, raw)
		}
	}
	if d.Details.Category != "task_started" || d.Details.Body != "npm test" {
		t.Fatalf("notification changed: %+v", d.Details)
	}
}

// The review's case: a claude event from pane %3 in a directory two panes share
// lands on %3, not on whichever row the project match would have picked.
func TestInventoryClaudeEventLandsOnItsPane(t *testing.T) {
	now := inventoryClock()
	h, ok := notifier.ParseHook([]byte(`{"hook_event_name":"PermissionRequest","session_id":"c1","tool_name":"Bash","tool_input":{"command":"npm test"},"cwd":"/Users/me/repos/shinphony"}`))
	if !ok {
		t.Fatal("hook payload")
	}
	e, ok := agentEventFromHook("claude", h, tmuxRouteEnv())
	if !ok {
		t.Fatal("event")
	}
	attachRouteFacts(&e, h.Session, 4321, tmuxRouteEnv())
	tr := newTracker()
	if d := tr.decide(e, settings{TurnCompletePush: "all", RateLimitPerMinute: 600}, now); d.Status != "attention" {
		t.Fatalf("claude approval: %+v", d)
	}
	windows := strings.Join([]string{
		tmuxLineOn("/tmp/tmux-1000/default", "work", 0, "editor", "1763249990", "%2", "/Users/me/repos/shinphony", "zsh"),
		tmuxLineOn("/tmp/tmux-1000/default", "work", 1, "tests", "1763249990", "%3", "/Users/me/repos/shinphony", "zsh"),
	}, "\n") + "\n"
	inv := buildInventory(context.Background(), inventoryFixtureSources{
		stdout: map[string][]byte{"tmux": []byte(windows)},
		states: tr.inventoryStates(now),
		now:    now,
	}.options())
	want := map[string]struct{ state, source string }{
		"editor": {"working", "mux"},
		"tests":  {"approval", "hook"},
	}
	if len(inv.Conversations) != 2 {
		t.Fatalf("got %d rows", len(inv.Conversations))
	}
	for _, c := range inv.Conversations {
		if w := want[c.Title]; w.state != c.State || w.source != c.StateSource {
			t.Fatalf("%s: %s/%s, want %s/%s", c.Title, c.State, c.StateSource, w.state, w.source)
		}
		if c.Title == "tests" && c.Message != "Allow Bash?" {
			t.Fatalf("message %q", c.Message)
		}
	}
}

// A pane or terminal hosts one agent at a time. Several tracked sessions naming
// the same route are the same conversation over time, and the one seen last is
// the occupant - otherwise a killed agent (or agy, which reports no session end)
// would shadow its own pane for a day.
func TestInventoryNewestSessionOwnsThePane(t *testing.T) {
	now := inventoryClock()
	windows := tmuxLineOn("/tmp/tmux-1000/default", "work", 0, "editor", "1763249990", "%3", "/Users/me/repos/shinphony", "zsh") + "\n"
	states := []trackedConversation{
		{Agent: "claude", Mux: "tmux", Pane: "%3", TmuxSocket: "/tmp/tmux-1000/default", Project: "shinphony", State: "question", Message: "old", Since: now.Unix() - 7200, Seen: now.Unix() - 7100},
		{Agent: "codex", Mux: "tmux", Pane: "%3", TmuxSocket: "/tmp/tmux-1000/default", Project: "shinphony", State: "working", Since: now.Unix() - 60, Seen: now.Unix() - 10},
	}
	inv := buildInventory(context.Background(), inventoryFixtureSources{
		stdout: map[string][]byte{"tmux": []byte(windows)}, states: states, now: now,
	}.options())
	if len(inv.Conversations) != 1 {
		t.Fatalf("got %d rows", len(inv.Conversations))
	}
	c := inv.Conversations[0]
	if c.State != "working" || c.StateSource != "hook" || (c.Agent == nil || *c.Agent != "codex") {
		t.Fatalf("the stale session won: %+v", c)
	}
	// The same rule on the tracker side, and it must not drop a lone session.
	tr := newTracker()
	s := settings{TurnCompletePush: "all", RateLimitPerMinute: 600}
	e := agentEvent{Agent: "claude", Session: sessionKey("claude", "s"), Kind: "prompt", Mux: "tmux",
		Source: &hookSource{Agent: "claude", Thread: "s", ParentPID: 42, Tmux: "/tmp/tmux-1000/default,1,0", Pane: "%3"}}
	tr.decide(e, s, now.Add(-2*time.Hour))
	e.Session = sessionKey("claude", "s2")
	e.Source.Thread = "s2"
	tr.decide(e, s, now)
	snap := tr.inventoryStates(now)
	if len(snap) != 1 || snap[0].State != "working" {
		t.Fatalf("tracker snapshot kept the stale session: %+v", snap)
	}
}

// An event that names a pane this host does not list must not be re-attributed
// to another row in the same directory: a route is an identity, not a hint.
func TestInventoryRouteFactsSkipTheProjectFallback(t *testing.T) {
	now := inventoryClock()
	sources := inventoryFixtureSources{
		stdout: map[string][]byte{"tmux": []byte(tmuxLine("work", 0, "editor", "1763249990", "%2", "/Users/me/repos/shinphony", "zsh") + "\n")},
		states: []trackedConversation{
			{Agent: "claude", Mux: "tmux", Pane: "%99", TmuxSocket: "/tmp/tmux-1000/default", Project: "shinphony", State: "question", Message: "q", Since: now.Unix() - 30, Seen: now.Unix() - 5},
		},
		now: now,
	}
	if c := buildInventory(context.Background(), sources.options()).Conversations[0]; c.StateSource != "mux" {
		t.Fatalf("a stale route fell back to the project: %s/%s", c.State, c.StateSource)
	}
	// Without route facts (an old hook binary, or no multiplexer) the fallback
	// stays, because it is all that event can tell us.
	sources.states[0].Pane, sources.states[0].TmuxSocket = "", ""
	if c := buildInventory(context.Background(), sources.options()).Conversations[0]; c.StateSource != "hook" {
		t.Fatalf("the project fallback was lost: %s/%s", c.State, c.StateSource)
	}
}

// An older daemon rejects a source it does not expect. The notification matters
// more than the route, so the hook retries once without it.
func TestHookPostsWithoutRouteFactsToAnOldDaemon(t *testing.T) {
	dir := t.TempDir()
	ln, err := listenLocal(dir)
	if err != nil {
		t.Skip("no local socket here:", err)
	}
	var mu sync.Mutex
	var bodies []map[string]any
	failing := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		var body map[string]any
		if json.Unmarshal(raw, &body) != nil {
			t.Errorf("bad body: %s", raw)
		}
		mu.Lock()
		bodies = append(bodies, body)
		n := len(bodies)
		mu.Unlock()
		if n == 1 {
			http.Error(w, "invalid_event", 400) // an old daemon: no route facts
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"queued": true})
	})
	server := &http.Server{Handler: failing}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(ln) }()
	defer func() { server.Close(); <-done }()

	e := agentEvent{Agent: "claude", Session: sessionKey("claude", "s"), Kind: "prompt", Body: "fix it", Mux: "tmux"}
	attachRouteFacts(&e, "s", 4321, tmuxRouteEnv())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = postAgentEventCompat(ctx, dir, e); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("got %d posts", len(bodies))
	}
	if bodies[0]["source"] == nil || bodies[1]["source"] != nil {
		t.Fatalf("retry did not drop the source: %+v", bodies)
	}
	if bodies[1]["body"] != "fix it" || bodies[1]["agent"] != "claude" {
		t.Fatalf("the retry lost the event: %+v", bodies[1])
	}
}

// Anything that is not a validation rejection is not retried: a busy or broken
// daemon must see one event, not two.
func TestHookDoesNotRetryOtherFailures(t *testing.T) {
	dir := t.TempDir()
	ln, err := listenLocal(dir)
	if err != nil {
		t.Skip("no local socket here:", err)
	}
	var mu sync.Mutex
	posts := 0
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts++
		mu.Unlock()
		http.Error(w, "storage_unavailable", 503)
	})}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(ln) }()
	defer func() { server.Close(); <-done }()

	e := agentEvent{Agent: "claude", Session: sessionKey("claude", "s"), Kind: "prompt"}
	attachRouteFacts(&e, "s", 4321, hcRouteEnv())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = postAgentEventCompat(ctx, dir, e); err == nil {
		t.Fatal("a 503 must be reported")
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 1 {
		t.Fatalf("%d posts", posts)
	}
}

// routeKeyFromEvent and a row's routeKey are the same production helper: the
// hook's event and the inventory's rows must agree on what identifies a
// conversation, or a state joins nothing.
func routeKeyFromEvent(e agentEvent) string {
	if e.Source == nil {
		return ""
	}
	return routeKey(e.Source.HcSession, e.Source.HcAddress, tmuxSocketFrom(e.Source.Tmux), e.Source.Pane)
}

func (r inventoryRow) routeKey() string {
	return routeKey(r.hcSession, r.hcAddress, r.tmuxSocket, r.pane)
}
