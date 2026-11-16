package main

// State accuracy (plan H3): herdr's own words at full fidelity, plain shells
// that never claim work, the `kind` field that tells the App which is which, and
// the join that puts a tracked agent's state on its row. The join itself was
// already exact (route_facts_test.go); what these tests pin is what a row says
// when *no* hook describes it — the case an update's daemon restart leaves
// behind, and the case that made a whole inventory look mux-sourced.
import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

// inventoryAgo is inventoryNow minus n seconds, as the tmux activity field.
func inventoryAgo(seconds int64) string { return strconv.FormatInt(inventoryNow-seconds, 10) }

// hcStatus is one hc terminal with an explicit herdr status map, so a test can
// pin every word herdr may report (state, kind, msg) without a helper per case.
func hcStatus(address, name, app, state, kind, msg, cwd string, statusAgo int64) hcTerminal {
	t := hcTerminal{Address: address, Name: name, State: "live", PID: 4242, Cwd: cwd,
		CreatedMS: (inventoryNow - 3600) * 1000}
	if app != "" || state != "" || kind != "" || msg != "" {
		t.Status = map[string]any{"app": app, "state": state}
		if kind != "" {
			t.Status["kind"] = kind
		}
		if msg != "" {
			t.Status["msg"] = msg
		}
		t.StatusMS = (inventoryNow - statusAgo) * 1000
	}
	return t
}

// herdr reports idle, working, done, blocked and error; blocked carries the kind
// of request (permission, question, auth) and the program's own message. The
// inventory must not flatten those into working/idle: `done` after a finished
// turn and `blocked` while the agent waits for the user are the words the App
// now shows, and a blocked program is the one "needs you" a coarse row may say.
func TestInventoryHerdrStatusFidelity(t *testing.T) {
	for _, tc := range []struct {
		name, app, word, hcKind, msg       string
		statusAgo                          int64
		wantState, wantSource, wantMessage string
		wantKind                           string
	}{
		{"working", "codex", "working", "", "", 5, "working", "mux", "", "agent"},
		{"done", "codex", "done", "", "", 30, "done", "mux", "", "agent"},
		{"done-decays", "codex", "done", "", "", 32 * 3600, "idle", "mux", "", "agent"},
		{"idle", "codex", "idle", "", "", 600, "idle", "mux", "", "agent"},
		{"blocked-permission", "claude-code", "blocked", "permission", "Allow bash?", 12, "question", "mux", "Allow bash?", "agent"},
		{"blocked-question", "codex", "blocked", "question", "Which branch?", 12, "question", "mux", "Which branch?", "agent"},
		{"blocked-auth", "agy", "blocked", "auth", "Sign in to Antigravity", 12, "question", "mux", "Sign in to Antigravity", "agent"},
		{"blocked-no-message", "codex", "blocked", "", "", 12, "question", "mux", "", "agent"},
		{"error", "codex", "error", "", "", 12, "failed", "mux", "", "agent"},
		{"unknown-word", "codex", "thinking", "", "", 5, "working", "mux", "", "agent"},
		{"known-agent-no-word", "codex", "", "", "", 12, "unknown", "none", "", "agent"},
		{"shell-no-status", "", "", "", "", 0, "idle", "none", "", "shell"},
		{"shell-with-word", "", "idle", "", "", 600, "idle", "mux", "", "shell"},
	} {
		sources := inventoryFixtureSources{hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcStatus("t1", "term", tc.app, tc.word, tc.hcKind, tc.msg, "/Users/me/repos/shinphony", tc.statusAgo),
		}}}
		inv := buildInventory(context.Background(), sources.options())
		if len(inv.Conversations) != 1 {
			t.Fatalf("%s: got %d rows", tc.name, len(inv.Conversations))
		}
		c := inv.Conversations[0]
		if c.State != tc.wantState || c.StateSource != tc.wantSource || c.Message != tc.wantMessage || c.Kind != tc.wantKind {
			t.Fatalf("%s: %s/%s kind=%s msg=%q, want %s/%s kind=%s msg=%q",
				tc.name, c.State, c.StateSource, c.Kind, c.Message, tc.wantState, tc.wantSource, tc.wantKind, tc.wantMessage)
		}
	}
}

// A pane whose program is not an agent is a shell: its output is not work, so it
// is quiet — never "working" because something was printed a second ago.
func TestInventoryShellsAreNeverWorking(t *testing.T) {
	sources := inventoryFixtureSources{
		stdout: map[string][]byte{"tmux": []byte(strings.Join([]string{
			tmuxLine("work", 0, "hot-shell", inventoryAgo(5), "%1", "/Users/me/repos/shinphony", "zsh"),
			tmuxLine("work", 1, "warm-shell", inventoryAgo(30), "%2", "/var/log", "tail"),
			tmuxLine("work", 2, "hot-agent", inventoryAgo(5), "%3", "/Users/me/repos/shinphony", "codex"),
			tmuxLine("work", 3, "quiet-agent", inventoryAgo(3600), "%4", "/Users/me/repos/shinphony", "codex"),
		}, "\n") + "\n")},
	}
	want := map[string]struct{ state, source, kind string }{
		"hot-shell":   {"idle", "none", "shell"},
		"warm-shell":  {"idle", "none", "shell"},
		"hot-agent":   {"working", "mux", "agent"},
		"quiet-agent": {"idle", "mux", "agent"},
	}
	inv := buildInventory(context.Background(), sources.options())
	if len(inv.Conversations) != len(want) {
		t.Fatalf("got %d rows", len(inv.Conversations))
	}
	for _, c := range inv.Conversations {
		w := want[c.Title]
		if c.State != w.state || c.StateSource != w.source || c.Kind != w.kind {
			t.Fatalf("%s: %s/%s kind=%s, want %s/%s kind=%s", c.Title, c.State, c.StateSource, c.Kind, w.state, w.source, w.kind)
		}
		if w.kind == "shell" && c.Agent != nil {
			t.Fatalf("%s: a shell has an agent: %q", c.Title, *c.Agent)
		}
	}
}

// The join is what turns a shell into an agent row: a hook event for the pane
// names the agent and its state, whatever the foreground command looks like.
func TestInventoryHookStateTurnsAShellIntoAnAgentRow(t *testing.T) {
	sources := inventoryFixtureSources{
		stdout: map[string][]byte{"tmux": []byte(
			tmuxLine("work", 0, "claude-here", inventoryAgo(5), "%1", "/Users/me/repos/shinphony", "node") + "\n")},
		states: []trackedConversation{
			{Agent: "claude", Mux: "tmux", Pane: "%1", TmuxSocket: "/tmp/tmux-501/default", Project: "shinphony",
				State: "question", Message: "Which branch?", Since: inventoryNow - 30, Seen: inventoryNow - 5},
		},
	}
	c := buildInventory(context.Background(), sources.options()).Conversations[0]
	if c.Kind != "agent" || c.Agent == nil || *c.Agent != "claude" {
		t.Fatalf("join did not make an agent row: %+v", c)
	}
	if c.State != "question" || c.StateSource != "hook" || c.Message != "Which branch?" {
		t.Fatalf("hook state did not win: %s/%s %q", c.State, c.StateSource, c.Message)
	}
	// The same pane without the hook is a shell again, and quiet.
	sources.states = nil
	if c := buildInventory(context.Background(), sources.options()).Conversations[0]; c.Kind != "shell" || c.State != "idle" {
		t.Fatalf("a node pane without a hook is a shell: %s kind=%s", c.State, c.Kind)
	}
}

// Every mux reports a row identity; every row says which of the two it is, so an
// App never has to guess from a null agent.
func TestInventoryKindOnEveryMux(t *testing.T) {
	sources := inventoryFixtureSources{
		stdout: map[string][]byte{
			"tmux":   []byte(tmuxLine("work", 0, "editor", inventoryAgo(5), "%1", "/tmp", "zsh") + "\n"),
			"zellij": []byte("dev\n"),
			"screen": []byte("There are screens on:\n\t12345.pts-0.host\t(Detached)\n2 Sockets in /tmp/screens.\n"),
		},
		hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcStatus("t1", "claude-main", "claude-code", "working", "", "", "/tmp", 5),
			hcStatus("t2", "plain", "", "", "", "", "/tmp", 0),
		}},
	}
	inv := buildInventory(context.Background(), sources.options())
	if len(inv.Conversations) != 5 {
		t.Fatalf("got %d rows", len(inv.Conversations))
	}
	for _, c := range inv.Conversations {
		want := "shell"
		if c.Agent != nil {
			want = "agent"
		}
		if c.Kind != want {
			t.Fatalf("%s (%s): kind %q, want %q", c.Title, c.Mux, c.Kind, want)
		}
		if c.Kind == "shell" && c.State == "working" {
			t.Fatalf("%s: a shell said working", c.Title)
		}
	}
}

// The join the plan asks to verify end to end: a real hook event (route facts
// from the terminal's environment, the daemon's own decision) becomes the state
// of the row it names — for an hc terminal and for a tmux pane.
func TestInventoryJoinsTrackerEventsForBothRoutes(t *testing.T) {
	now := inventoryClock()
	tr := newTracker()
	s := settings{TurnCompletePush: "all", RateLimitPerMinute: 600}

	// hc: a codex question asked inside t2.
	hcEvent := agentEvent{Agent: "codex", Session: sessionKey("codex", "hc-thread"), Kind: "question",
		Mux: "hc", Project: "shinphony", Title: "Allow bash?", Body: "rm -rf build"}
	attachRouteFacts(&hcEvent, "hc-thread", 4321, hcRouteEnv())
	if !hcEvent.valid() {
		t.Fatalf("event invalid: %+v", hcEvent)
	}
	// tmux: a claude turn that just started inside %3.
	tmuxEvent := agentEvent{Agent: "claude", Session: sessionKey("claude", "tmux-thread"), Kind: "prompt",
		Mux: "tmux", Project: "shinphony", Body: "fix the build"}
	attachRouteFacts(&tmuxEvent, "tmux-thread", 4321, tmuxRouteEnv())
	if !tmuxEvent.valid() {
		t.Fatalf("event invalid: %+v", tmuxEvent)
	}
	for _, e := range []agentEvent{hcEvent, tmuxEvent} {
		if d := tr.decide(e, s, now); d.Status == "" {
			t.Fatalf("event not accepted: %+v", d)
		}
	}
	states := tr.inventoryStates(now)
	if len(states) != 2 {
		t.Fatalf("tracker snapshot: %+v", states)
	}
	sources := inventoryFixtureSources{
		now: now,
		hc: hcListing{Session: "default", Terminals: []hcTerminal{
			// The route facts name t7 in the default core session.
			hcStatus("t7", "codex-main", "codex", "idle", "", "", "/Users/me/repos/shinphony", 600),
		}},
		stdout: map[string][]byte{"tmux": []byte(
			tmuxLineOn("/tmp/tmux-1000/default", "work", 1, "claude-here", inventoryAgo(600), "%3", "/Users/me/repos/shinphony", "zsh") + "\n")},
		states: states,
	}
	want := map[string]struct{ state, source, kind, message string }{
		"codex-main":  {"question", "hook", "agent", "Allow bash?"},
		"claude-here": {"working", "hook", "agent", ""},
	}
	inv := buildInventory(context.Background(), sources.options())
	if len(inv.Conversations) != len(want) {
		t.Fatalf("got %d rows", len(inv.Conversations))
	}
	for _, c := range inv.Conversations {
		w := want[c.Title]
		if c.State != w.state || c.StateSource != w.source || c.Kind != w.kind || c.Message != w.message {
			t.Fatalf("%s: %s/%s kind=%s msg=%q, want %+v", c.Title, c.State, c.StateSource, c.Kind, c.Message, w)
		}
	}
}

// Without a daemon the CLI prints the mux rows — valid, but with no hook state
// anywhere. The document must say so instead of leaving the reader to guess why
// every row is coarse.
func TestInventoryFallbackExplainsMissingHookState(t *testing.T) {
	sources := inventoryFixtureSources{
		stdout: map[string][]byte{"tmux": []byte(tmuxLine("work", 0, "editor", inventoryAgo(5), "%1", "/tmp", "codex") + "\n")},
		fail:   map[string]bool{"zellij": true},
	}
	inv := inventoryFallback(context.Background(), sources.options())
	if len(inv.Errors) < 2 || inv.Errors[0] != "daemon_unavailable" || inv.Errors[1] != "zellij_unavailable" {
		t.Fatalf("errors %v", inv.Errors)
	}
	if len(inv.Conversations) != 1 || inv.Conversations[0].StateSource == "hook" {
		t.Fatalf("fallback rows: %+v", inv.Conversations)
	}
	// The document is still a valid inventory: the App keeps rendering it.
	raw, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	var back inventory
	if err = json.Unmarshal(raw, &back); err != nil || back.Schema != inventorySchema || back.Conversations == nil {
		t.Fatalf("%v %s", err, raw)
	}
}

// A fixture row may say "needs you" from herdr (a blocked program), so the
// contract allows a question from the mux — but only from hc, and never an
// approval, which only a hook knows.
func TestInventoryFixtureQuestionFromHerdrIsAllowed(t *testing.T) {
	agent := "codex"
	blocked := inventoryConversation{ID: "c_1111111111111111", Mux: "hc", Kind: "agent", Agent: &agent,
		State: "question", StateSource: "mux", Route: inventoryRoute{Version: 1, Multiplexer: "hc"}}
	if err := checkInventoryContractRow(blocked, map[string]bool{blocked.ID: true}); err != nil {
		t.Fatalf("herdr blocked rejected: %v", err)
	}
	blocked.Mux, blocked.Route.Multiplexer = "tmux", "tmux"
	if err := checkInventoryContractRow(blocked, map[string]bool{blocked.ID: true}); err == nil {
		t.Fatal("a tmux row claimed needs-you")
	}
	approval := inventoryConversation{ID: "c_1111111111111111", Mux: "hc", Kind: "agent", Agent: &agent,
		State: "approval", StateSource: "mux", Route: inventoryRoute{Version: 1, Multiplexer: "hc"}}
	if err := checkInventoryContractRow(approval, map[string]bool{approval.ID: true}); err == nil {
		t.Fatal("a coarse row claimed approval")
	}
	// `kind` must agree with `agent`: one is the other, spelled for the App.
	mismatched := inventoryConversation{ID: "c_1111111111111111", Mux: "hc", Kind: "shell", Agent: &agent,
		State: "idle", StateSource: "mux", Route: inventoryRoute{Version: 1, Multiplexer: "hc"}}
	if err := checkInventoryContractRow(mismatched, map[string]bool{mismatched.ID: true}); err == nil {
		t.Fatal("a row said shell but named an agent")
	}
}

// The tracker keeps herdr's own word for a blocked program all the way to the
// row: the message a blocked program wrote is what the App shows.
func TestInventoryBlockedMessageIsBoundedAndClean(t *testing.T) {
	sources := inventoryFixtureSources{hc: hcListing{Session: "default", Terminals: []hcTerminal{
		hcStatus("t1", "term", "codex", "blocked", "permission",
			"Allow\tbash?\u202e "+strings.Repeat("x", 300), "/tmp", 12),
	}}}
	c := buildInventory(context.Background(), sources.options()).Conversations[0]
	if strings.ContainsAny(c.Message, "\n\t\x1b") || strings.ContainsRune(c.Message, 0x202e) {
		t.Fatalf("message not cleaned: %q", c.Message)
	}
	if n := len([]rune(c.Message)); n != 120 {
		t.Fatalf("message runes %d", n)
	}
	if !strings.HasPrefix(c.Message, "Allow bash?") {
		t.Fatalf("message %q", c.Message)
	}
}

// A hc row's since is the status change, so a done turn decays on herdr's clock
// and not on when this document happened to be built.
func TestInventoryHerdrDoneDecaysFromStatusTime(t *testing.T) {
	sources := inventoryFixtureSources{hc: hcListing{Session: "default", Terminals: []hcTerminal{
		hcStatus("t1", "fresh", "codex", "done", "", "", "/tmp", 3600),
		hcStatus("t2", "stale", "codex", "done", "", "", "/tmp", int64((25 * time.Hour).Seconds())),
	}}}
	want := map[string]string{"fresh": "done", "stale": "idle"}
	for _, c := range buildInventory(context.Background(), sources.options()).Conversations {
		if c.State != want[c.Title] {
			t.Fatalf("%s: %s, want %s", c.Title, c.State, want[c.Title])
		}
		if c.StateSource != "mux" {
			t.Fatalf("%s: source %s", c.Title, c.StateSource)
		}
	}
}
