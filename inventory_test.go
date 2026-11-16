package main

// Inventory v1 (plan H1): the hook owns the merge of every conversation on this
// host with the state its agent tracker knows. These tests pin the JSON the App
// consumes (testdata/inventory) and the rules behind it: stable ids, the tracker
// override, mux state never becoming "needs you", truncation and clean text.
import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var updateInventoryFixtures = flag.Bool("update-inventory", false, "rewrite testdata/inventory fixtures")

// inventoryNow is a fixed clock: fixtures must not depend on the test run time.
const inventoryNow = int64(1763250000)

func inventoryClock() time.Time { return time.Unix(inventoryNow, 0).UTC() }

// inventoryFixtureSources is every source the builder reads, faked. Find/Run are
// the tmux, zellij and screen path; Hc is the hc core listing; States is the
// tracker snapshot the daemon would hand over.
type inventoryFixtureSources struct {
	now    time.Time
	stdout map[string][]byte
	stderr map[string][]byte
	fail   map[string]bool
	absent map[string]bool
	hc     hcListing
	hcErr  error
	states []trackedConversation
}

func (f inventoryFixtureSources) options() inventoryOptions {
	clock := f.now
	if clock.IsZero() {
		clock = inventoryClock()
	}
	return inventoryOptions{
		Now:  clock,
		Find: func(tool string) string { return findFakeTool(f.absent, tool) },
		Run: func(_ context.Context, path string, _ []string) ([]byte, []byte, error) {
			tool := filepath.Base(path)
			if f.fail[tool] {
				return f.stdout[tool], f.stderr[tool], errors.New("exit status 1")
			}
			return f.stdout[tool], nil, nil
		},
		Hc:     func(context.Context) (hcListing, error) { return f.hc, f.hcErr },
		States: func(time.Time) []trackedConversation { return f.states },
	}
}

func findFakeTool(absent map[string]bool, tool string) string {
	if absent[tool] {
		return ""
	}
	return "/fake/" + tool
}

// hcRow builds one live terminal the way terminal.list reports it.
func hcRow(address, name, parent, app, state, cwd, where string, createdMS, statusMS int64) hcTerminal {
	t := hcTerminal{Address: address, Name: name, Parent: parent, State: "live", CreatedMS: createdMS, PID: 4242, Cwd: cwd}
	if where != "" {
		t.Labels = map[string]any{"where": where}
	}
	if app != "" || state != "" {
		t.Status = map[string]any{"app": app, "state": state}
		t.StatusMS = statusMS
	}
	return t
}

// tmuxLine is one `list-windows -a -F` row in the order of tmuxInventoryFormat:
// session, session id, window index, window name, window id, activity, pane,
// cwd, foreground command, socket. The session and window ids are derived from
// the index so a row's tests read as the same conversation.
func tmuxLine(session string, index int, window, activity, pane, cwd, command string) string {
	return tmuxLineOn("/tmp/tmux-501/default", session, index, window, activity, pane, cwd, command)
}

// tmuxLineOn is tmuxLine for a specific server socket: a pane id only identifies
// a conversation inside the server it came from.
func tmuxLineOn(socket, session string, index int, window, activity, pane, cwd, command string) string {
	return strings.Join([]string{session, "$" + itoa(index+1), itoa(index), window, "@" + itoa(index+1), activity, pane, cwd, command, socket}, "\t")
}

// ---------------------------------------------------------------------------
// Fixtures: the App contract.
// ---------------------------------------------------------------------------

func TestInventoryFixtureAllStates(t *testing.T) {
	// Every state the App may have to draw, hook-sourced and coarse: the tracker's
	// own states, herdr's words (working/done/idle/blocked/error), a known agent
	// herdr never reported a status for, a plain shell, and a tmux pane whose hook
	// state is what makes it an agent row.
	sources := inventoryFixtureSources{
		stdout: map[string][]byte{
			"tmux": []byte(strings.Join([]string{
				tmuxLine("work", 0, "editor", "1763249970", "%1", "/Users/me/repos/shinphony", "zsh"),
				tmuxLine("work", 1, "logs", "1763242800", "%2", "/var/log", "tail"),
				tmuxLine("work", 2, "codex-pane", "1763249990", "%3", "/Users/me/repos/laclune", "codex"),
				tmuxLine("work", 3, "claude-pane", "1763243000", "%4", "/Users/me/repos/shinphony", "zsh"),
			}, "\n") + "\n"),
		},
		hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcRow("t1", "claude-main", "", "claude-code", "blocked", "/Users/me/repos/shinphony", "Shinphony / 1", inventoryNow*1000-3600000, inventoryNow*1000-20000),
			hcRow("t2", "codex-helper", "t1", "codex", "working", "/Users/me/repos/shinphony", "Shinphony / 1", inventoryNow*1000-2000000, inventoryNow*1000-10000),
			hcRow("t3", "agy-scan", "", "antigravity", "working", "/Users/me/repos/laclune", "Laclune / 1", inventoryNow*1000-5000000, inventoryNow*1000-5000),
			hcRow("t4", "pi-helper", "", "pi", "idle", "/Users/me/repos/shinphony", "Shinphony / 1", inventoryNow*1000-9000000, inventoryNow*1000-600000),
			hcRow("t5", "codex-old", "", "codex", "done", "/Users/me/repos/other", "Other / 1", inventoryNow*1000-3000000, inventoryNow*1000-30000),
			hcRow("t6", "", "", "", "", "/tmp", "", inventoryNow*1000-8000000, 0),
			// herdr's own words, no hook in sight.
			hcStatus("t7", "herdr-blocked", "codex", "blocked", "question", "Allow bash?", "/Users/me/repos/shinphony", 15),
			hcStatus("t8", "herdr-error", "antigravity", "error", "", "", "/Users/me/repos/laclune", 25),
			hcStatus("t9", "herdr-done", "codex", "done", "", "", "/Users/me/repos/shinphony", 35),
			hcStatus("t10", "codex-nostatus", "codex", "", "", "", "/Users/me/repos/shinphony", 0),
		}},
		states: []trackedConversation{
			{Agent: "claude", Mux: "hc", HcAddress: "t1", Project: "shinphony", State: "question", Message: "Which branch?", Since: inventoryNow - 90, Seen: inventoryNow - 10},
			{Agent: "codex", Mux: "hc", HcAddress: "t2", Project: "shinphony", State: "approval", Message: "Allow bash?", Since: inventoryNow - 40, Seen: inventoryNow - 10},
			{Agent: "agy", Mux: "hc", Project: "laclune", State: "failed", Since: inventoryNow - 200, Seen: inventoryNow - 20},
			{Agent: "codex", Mux: "hc", HcAddress: "t5", Project: "other", State: "done", Since: inventoryNow - 3600, Seen: inventoryNow - 30},
			{Agent: "claude", Mux: "tmux", Pane: "%4", TmuxSocket: "/tmp/tmux-501/default", Project: "shinphony", State: "working", Since: inventoryNow - 50, Seen: inventoryNow - 45},
		},
	}
	checkInventoryFixture(t, "all-states.json", buildInventory(context.Background(), sources.options()))
}

func TestInventoryFixtureEachMux(t *testing.T) {
	sources := inventoryFixtureSources{
		stdout: map[string][]byte{
			"tmux": []byte(strings.Join([]string{
				tmuxLine("work", 0, "editor", "1763249970", "%1", "/Users/me/repos/shinphony", "codex"),
				"this line is not a window",
				tmuxLine("work", 1, "logs", "1763242800", "%2", "/var/log", "tail"),
				// Output a second ago is not work: a shell is quiet.
				tmuxLine("work", 2, "busy-shell", "1763249995", "%3", "/Users/me/repos/shinphony", "zsh"),
			}, "\n") + "\n"),
			"zellij": []byte("dev\nops\n"),
			"screen": []byte("There are screens on:\n\t12345.pts-0.host\t(Detached)\n2 Sockets in /tmp/screens.\n"),
		},
		hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcRow("t1", "claude-main", "", "claude-code", "done", "/Users/me/repos/shinphony", "Shinphony / 1", inventoryNow*1000-3600000, inventoryNow*1000-200000),
		}},
	}
	checkInventoryFixture(t, "each-mux.json", buildInventory(context.Background(), sources.options()))
}

func TestInventoryFixtureHcHelpers(t *testing.T) {
	sources := inventoryFixtureSources{
		hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcRow("t1", "claude-main", "", "claude-code", "working", "/Users/me/repos/shinphony", "Shinphony / 1", inventoryNow*1000-3600000, inventoryNow*1000-20000),
			hcRow("t2", "codex-helper", "t1", "codex", "working", "/Users/me/repos/shinphony", "Shinphony / 1", inventoryNow*1000-600000, inventoryNow*1000-5000),
			hcRow("t3", "pi-helper", "t2", "pi", "idle", "/Users/me/repos/shinphony", "Shinphony / 1", inventoryNow*1000-600000, inventoryNow*1000-400000),
			hcRow("t4", "orphan", "t9", "codex", "idle", "/Users/me/repos/elsewhere", "Other / 2", inventoryNow*1000-600000, inventoryNow*1000-500000),
		}},
	}
	checkInventoryFixture(t, "hc-helpers.json", buildInventory(context.Background(), sources.options()))
}

func TestInventoryFixtureErrors(t *testing.T) {
	sources := inventoryFixtureSources{
		absent: map[string]bool{"zellij": true, "screen": true},
		fail:   map[string]bool{"tmux": true},
		stderr: map[string][]byte{"tmux": []byte("tmux: boom\n")},
		hcErr:  errors.New("core wedged"),
	}
	checkInventoryFixture(t, "errors.json", buildInventory(context.Background(), sources.options()))
}

func TestInventoryFixtureTruncation(t *testing.T) {
	var windows []string
	for i := 0; i < 210; i++ {
		activity := itoa(1763150000 - i) // old output: idle, older for larger i
		command := "zsh"                 // a shell: quiet, and dropped first
		if i < 5 {
			activity = "1763249990" // a turn that just ran
			command = "codex"       // an agent at work: it must survive the limit
		}
		windows = append(windows, tmuxLine("work", i, "w"+itoa(i), activity, "%"+itoa(100+i), "/Users/me/repos/trunc", command))
	}
	sources := inventoryFixtureSources{
		stdout: map[string][]byte{"tmux": []byte(strings.Join(windows, "\n") + "\n")},
		hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcRow("t0", "old-parent", "", "codex", "idle", "/Users/me/repos/trunc", "Trunc / 1", 1000, 0),
			hcRow("t1", "new-helper", "t0", "codex", "working", "/Users/me/repos/trunc", "Trunc / 1", inventoryNow*1000-1000, inventoryNow*1000-1000),
		}},
	}
	inv := buildInventory(context.Background(), sources.options())
	if len(inv.Conversations) != 200 {
		t.Fatalf("want 200 conversations, got %d", len(inv.Conversations))
	}
	checkInventoryFixture(t, "truncation.json", inv)
}

func checkInventoryFixture(t *testing.T, name string, got inventory) {
	t.Helper()
	got.GeneratedAt = inventoryNow
	raw, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("testdata", "inventory", name)
	if *updateInventoryFixtures {
		if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing fixture %s (run: go test -run Inventory -update-inventory): %v", path, err)
	}
	var a, b any
	if err = json.Unmarshal(want, &a); err != nil {
		t.Fatalf("%s is not JSON: %v", path, err)
	}
	if err = json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("%s differs\n--- want ---\n%s\n--- got ---\n%s", path, want, raw)
	}
}

// Every fixture is also checked against the contract itself, so a broken
// fixture cannot become the App's source of truth.
func TestInventoryFixturesMatchContract(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "inventory"))
	if err != nil {
		t.Fatalf("no fixtures yet: %v", err)
	}
	states := map[string]bool{"question": true, "approval": true, "working": true, "done": true, "failed": true, "idle": true, "unknown": true}
	muxes := map[string]bool{"hc": true, "tmux": true, "rex": true, "zellij": true, "shell": true}
	ids := regexp.MustCompile(`^c_[0-9a-f]{16}$`)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("testdata", "inventory", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var inv inventory
		if err = json.Unmarshal(raw, &inv); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		if inv.Schema != 1 || inv.GeneratedAt == 0 || inv.Conversations == nil || inv.Errors == nil {
			t.Fatalf("%s: schema/generatedAt/conversations/errors missing", entry.Name())
		}
		if len(inv.Conversations) > 200 {
			t.Fatalf("%s: %d conversations", entry.Name(), len(inv.Conversations))
		}
		seen := map[string]bool{}
		for _, c := range inv.Conversations {
			if !ids.MatchString(c.ID) || seen[c.ID] {
				t.Fatalf("%s: bad or duplicate id %q", entry.Name(), c.ID)
			}
			seen[c.ID] = true
			if !muxes[c.Mux] || !states[c.State] {
				t.Fatalf("%s: bad mux/state %q/%q", entry.Name(), c.Mux, c.State)
			}
			if err = checkInventoryContractRow(c, seen); err != nil {
				t.Fatalf("%s: %v", entry.Name(), err)
			}
			if c.Parent != "" {
				// The parent must be a row in this document, never dangling.
				found := false
				for _, other := range inv.Conversations {
					if other.ID == c.Parent {
						found = true
					}
				}
				if !found {
					t.Fatalf("%s: dangling parent %q", entry.Name(), c.Parent)
				}
			}
		}
	}
}

// checkInventoryContractRow is one row's share of the contract, used by the
// fixture check and by the tests that pin a single rule. `ids` is every id the
// document already carries (for the duplicate check).
func checkInventoryContractRow(c inventoryConversation, ids map[string]bool) error {
	if c.StateSource != "hook" && c.StateSource != "mux" && c.StateSource != "none" {
		return fmt.Errorf("bad stateSource %q", c.StateSource)
	}
	if len([]rune(c.Message)) > 120 || len([]rune(c.Title)) > 120 {
		return errors.New("title/message too long")
	}
	// "Needs you" comes from a hook, or from herdr's own `blocked` (an hc row
	// whose program is waiting for the user). An approval is only ever a hook:
	// no multiplexer can tell that a program is asking permission.
	if c.State == "approval" && c.StateSource != "hook" {
		return fmt.Errorf("approval from %s", c.StateSource)
	}
	if c.State == "question" && c.StateSource != "hook" && c.Mux != "hc" {
		return fmt.Errorf("question from %s on %s", c.StateSource, c.Mux)
	}
	// `kind` is exactly "an agent identity is present", spelled for the App.
	if c.Kind != "agent" && c.Kind != "shell" {
		return fmt.Errorf("bad kind %q", c.Kind)
	}
	if (c.Kind == "agent") != (c.Agent != nil) {
		return fmt.Errorf("kind %q with agent %v", c.Kind, c.Agent)
	}
	if c.Kind == "shell" && c.State == "working" {
		return errors.New("a shell said working")
	}
	if c.Route.Version != 1 || c.Route.Multiplexer != c.Mux {
		return fmt.Errorf("route does not describe the row: %+v", c.Route)
	}
	return nil
}

// ---------------------------------------------------------------------------
// State rules.
// ---------------------------------------------------------------------------

func TestInventoryHerdrWordsSurvive(t *testing.T) {
	now := inventoryClock()
	for _, tc := range []struct{ app, state, want, source string }{
		{"codex", "working", "working", "mux"},
		{"codex", "done", "done", "mux"},
		{"codex", "idle", "idle", "mux"},
		{"codex", "blocked", "question", "mux"},
		{"codex", "error", "failed", "mux"},
		// A recognised agent whose status is null has told us nothing yet.
		{"codex", "", "unknown", "none"},
		// A plain shell is quiet; herdr said nothing about it.
		{"", "", "idle", "none"},
	} {
		sources := inventoryFixtureSources{hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcRow("t1", "a", "", tc.app, tc.state, "/tmp", "", inventoryNow*1000-900000, inventoryNow*1000-600000),
		}}}
		inv := buildInventory(context.Background(), sources.options())
		if len(inv.Conversations) != 1 {
			t.Fatalf("%q/%q: got %d rows", tc.app, tc.state, len(inv.Conversations))
		}
		c := inv.Conversations[0]
		if c.State != tc.want || c.StateSource != tc.source {
			t.Fatalf("hc %q/%q → %s/%s, want %s/%s", tc.app, tc.state, c.State, c.StateSource, tc.want, tc.source)
		}
		// The status change is the row's clock; a terminal herdr never reported a
		// status for only has its creation.
		wantSince := now.Unix() - 600
		if tc.state == "" && tc.app == "" {
			wantSince = now.Unix() - 900
		}
		if c.Since != wantSince {
			t.Fatalf("hc %q/%q: since %d, want %d", tc.app, tc.state, c.Since, wantSince)
		}
	}
}

func TestInventoryRecentActivityIsWorking(t *testing.T) {
	sources := inventoryFixtureSources{
		hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcRow("t1", "recent", "", "codex", "done", "/tmp", "", inventoryNow*1000-900000, inventoryNow*1000-5000),
			hcRow("t2", "quiet", "", "codex", "done", "/tmp", "", inventoryNow*1000-900000, inventoryNow*1000-500000),
		}},
		stdout: map[string][]byte{"tmux": []byte(strings.Join([]string{
			tmuxLine("work", 0, "hot", "1763249995", "%1", "/tmp", "zsh"),
			tmuxLine("work", 1, "cold", "1763150000", "%2", "/tmp", "zsh"),
		}, "\n") + "\n")},
	}
	inv := buildInventory(context.Background(), sources.options())
	// Herdr's `done` is herdr's own word now; a tmux pane says working only for a
	// program that is an agent — a shell's output is not work.
	want := map[string]struct{ state, source string }{
		"recent": {"done", "mux"}, "quiet": {"done", "mux"},
		"hot": {"idle", "none"}, "cold": {"idle", "none"},
	}
	for _, c := range inv.Conversations {
		w := want[c.Title]
		if c.State != w.state || c.StateSource != w.source {
			t.Fatalf("%s: %s/%s, want %s/%s", c.Title, c.State, c.StateSource, w.state, w.source)
		}
	}
}

func TestInventoryHookStateWins(t *testing.T) {
	sources := inventoryFixtureSources{
		hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcRow("t1", "claude-main", "", "claude-code", "blocked", "/Users/me/repos/shinphony", "Shinphony / 1", inventoryNow*1000-900000, inventoryNow*1000-5000),
		}},
		states: []trackedConversation{
			{Agent: "claude", Mux: "hc", HcAddress: "t1", Project: "shinphony", State: "question", Message: "Which branch?", Since: inventoryNow - 30, Seen: inventoryNow - 5},
		},
	}
	c := buildInventory(context.Background(), sources.options()).Conversations[0]
	if c.State != "question" || c.StateSource != "hook" || c.Since != inventoryNow-30 || c.Message != "Which branch?" {
		t.Fatalf("hook state did not win: %+v", c)
	}
	if c.Agent == nil || *c.Agent != "claude" {
		t.Fatalf("agent: %v", c.Agent)
	}
}

// A project-level match is only a tie-breaker: two tabs in one folder make it
// ambiguous, and an ambiguous match must never claim "Needs you".
func TestInventoryAmbiguousProjectIsNotUsed(t *testing.T) {
	rows := []hcTerminal{
		hcRow("t1", "claude-a", "", "claude-code", "working", "/Users/me/repos/shinphony", "Shinphony / 1", 1000, inventoryNow*1000-5000),
		hcRow("t2", "claude-b", "", "claude-code", "working", "/Users/me/repos/shinphony", "Shinphony / 2", 1000, inventoryNow*1000-5000),
	}
	sources := inventoryFixtureSources{
		hc: hcListing{Session: "default", Terminals: rows},
		states: []trackedConversation{
			{Agent: "claude", Mux: "hc", Project: "shinphony", State: "question", Message: "Which branch?", Since: inventoryNow - 30, Seen: inventoryNow - 5},
		},
	}
	for _, c := range buildInventory(context.Background(), sources.options()).Conversations {
		if c.StateSource != "mux" || c.State != "working" {
			t.Fatalf("%s: %s/%s", c.Title, c.State, c.StateSource)
		}
	}
	// Two stale sessions for one row are ambiguous in the other direction too.
	sources.states = []trackedConversation{
		{Agent: "claude", Mux: "hc", Project: "shinphony", State: "question", Message: "a", Since: inventoryNow - 30, Seen: inventoryNow - 5},
		{Agent: "claude", Mux: "hc", Project: "shinphony", State: "approval", Message: "b", Since: inventoryNow - 20, Seen: inventoryNow - 5},
	}
	sources.hc = hcListing{Session: "default", Terminals: rows[:1]}
	if c := buildInventory(context.Background(), sources.options()).Conversations[0]; c.StateSource != "mux" {
		t.Fatalf("ambiguous states overrode a single row: %s/%s", c.State, c.StateSource)
	}
}

// A route is only exact inside the core session and tmux server it came from:
// every session has a t1, every server a %1.
func TestInventoryRouteMustMatchItsServer(t *testing.T) {
	sources := inventoryFixtureSources{
		hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcRow("t1", "claude-main", "", "claude-code", "working", "/Users/me/repos/shinphony", "Shinphony / 1", 1000, inventoryNow*1000-5000),
		}},
		stdout: map[string][]byte{"tmux": []byte(tmuxLine("work", 0, "editor", "1763249990", "%1", "/tmp", "zsh") + "\n")},
		states: []trackedConversation{
			{Agent: "claude", Mux: "hc", HcAddress: "t1", HcSession: "another-core", Project: "shinphony", State: "question", Message: "q", Since: inventoryNow - 30, Seen: inventoryNow - 5},
			{Agent: "codex", Mux: "tmux", Pane: "%1", TmuxSocket: "/tmp/other-socket", Project: "shinphony", State: "question", Message: "q", Since: inventoryNow - 30, Seen: inventoryNow - 5},
		},
	}
	for _, c := range buildInventory(context.Background(), sources.options()).Conversations {
		if c.StateSource == "hook" {
			t.Fatalf("%s took a state from another server: %s", c.Title, c.State)
		}
	}
}

func TestInventoryStaleHookStateIsIgnored(t *testing.T) {
	sources := inventoryFixtureSources{
		hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcRow("t1", "claude-main", "", "claude-code", "working", "/Users/me/repos/shinphony", "Shinphony / 1", 1000, inventoryNow*1000-5000),
		}},
		states: []trackedConversation{
			{Agent: "claude", Mux: "hc", Project: "shinphony", State: "question", Message: "Which branch?", Since: inventoryNow - 30, Seen: inventoryNow - 3*86400},
		},
	}
	if c := buildInventory(context.Background(), sources.options()).Conversations[0]; c.StateSource != "mux" {
		t.Fatalf("a three-day-old session overrode a live tab: %s/%s", c.State, c.StateSource)
	}
}

func TestInventoryStableIDs(t *testing.T) {
	id := regexp.MustCompile(`^c_[0-9a-f]{16}$`)
	sources := inventoryFixtureSources{
		stdout: map[string][]byte{"tmux": []byte(tmuxLine("work", 3, "editor", "1763249990", "%7", "/tmp", "zsh") + "\n")},
	}
	first := buildInventory(context.Background(), sources.options()).Conversations[0]
	if !id.MatchString(first.ID) {
		t.Fatalf("id %q", first.ID)
	}
	// A rename, a new state and a different clock keep the id.
	sources.stdout["tmux"] = []byte(tmuxLine("work", 3, "editor-renamed", "1763150000", "%7", "/tmp", "zsh") + "\n")
	sources.now = inventoryClock().Add(4 * time.Hour)
	second := buildInventory(context.Background(), sources.options()).Conversations[0]
	if first.ID != second.ID {
		t.Fatalf("id changed: %s → %s", first.ID, second.ID)
	}
	// Another window is another conversation.
	sources.stdout["tmux"] = []byte(tmuxLine("work", 4, "editor", "1763150000", "%8", "/tmp", "zsh") + "\n")
	if third := buildInventory(context.Background(), sources.options()).Conversations[0]; third.ID == first.ID {
		t.Fatal("different windows share an id")
	}
}

func TestInventoryCleanText(t *testing.T) {
	sources := inventoryFixtureSources{
		stdout: map[string][]byte{"tmux": []byte(tmuxLine("work\x1b[31m", 0, "ti\u202etle\x1b[31m", "1763249990", "%1", "/tmp/dir with", "zsh") + "\n")},
		states: []trackedConversation{
			{Agent: "codex", Mux: "tmux", Pane: "%1", Project: "dir with", State: "question", Message: strings.Repeat("问", 100) + "\n" + strings.Repeat("a", 100), Since: inventoryNow - 30, Seen: inventoryNow - 5},
		},
	}
	c := buildInventory(context.Background(), sources.options()).Conversations[0]
	if strings.ContainsAny(c.Title, "\n\t\x1b") || strings.ContainsRune(c.Title, 0x202e) {
		t.Fatalf("title not cleaned: %q", c.Title)
	}
	if strings.ContainsAny(c.Directory, "\n\t") || strings.ContainsAny(c.Group.Name, "\n\t") {
		t.Fatalf("directory/group not cleaned: %q %q", c.Directory, c.Group.Name)
	}
	if n := len([]rune(c.Message)); n != 120 {
		t.Fatalf("message runes %d", n)
	}
	if c.State != "question" {
		t.Fatalf("state %s", c.State)
	}
}

func TestInventoryTruncationKeepsNeedsYou(t *testing.T) {
	var windows []string
	for i := 0; i < 10; i++ {
		windows = append(windows, tmuxLine("work", i, "w"+itoa(i), itoa(1763150000-i), "%"+itoa(100+i), "/tmp", "zsh"))
	}
	sources := inventoryFixtureSources{
		stdout: map[string][]byte{"tmux": []byte(strings.Join(windows, "\n") + "\n")},
		states: []trackedConversation{
			{Agent: "codex", Mux: "tmux", Pane: "%109", Project: "", State: "question", Message: "Ready?", Since: inventoryNow - 3600, Seen: inventoryNow - 5},
		},
	}
	inv := buildInventoryWithLimit(context.Background(), sources.options(), 3)
	if len(inv.Conversations) != 3 {
		t.Fatalf("got %d rows", len(inv.Conversations))
	}
	found := false
	for _, c := range inv.Conversations {
		if c.State == "question" {
			found = true
		}
	}
	if !found {
		t.Fatal("the question row was dropped before idle rows")
	}
}

// ---------------------------------------------------------------------------
// Tracker snapshot (agent_events.go).
// ---------------------------------------------------------------------------

func trackedSnapshot(t *testing.T, events []agentEvent, now time.Time) []trackedConversation {
	t.Helper()
	tr := newTracker()
	s := settings{TurnCompletePush: "all", RateLimitPerMinute: 600}
	for i, e := range events {
		tr.decide(e, s, now.Add(time.Duration(i)*time.Second))
	}
	return tr.inventoryStates(now.Add(time.Duration(len(events)) * time.Second))
}

func TestTrackerInventoryStates(t *testing.T) {
	now := inventoryClock()
	base := agentEvent{Agent: "claude", Session: "s-a", Mux: "hc", Project: "shinphony"}
	steps := []struct {
		event agentEvent
		state string
	}{
		{agentEvent{Kind: "session_start"}, "idle"},
		{agentEvent{Kind: "prompt"}, "working"},
		{agentEvent{Kind: "question", Title: "Which branch?", Body: "1. main"}, "question"},
		{agentEvent{Kind: "prompt"}, "working"},
	}
	var events []agentEvent
	for _, step := range steps {
		e := base
		e.Kind, e.Title, e.Body = step.event.Kind, step.event.Title, step.event.Body
		events = append(events, e)
	}
	snap := trackedSnapshot(t, events, now)
	if len(snap) != 1 {
		t.Fatalf("got %d sessions", len(snap))
	}
	if snap[0].State != "working" || snap[0].Mux != "hc" || snap[0].Project != "shinphony" || snap[0].Agent != "claude" {
		t.Fatalf("%+v", snap[0])
	}

	// One event at a time: the state and the text a row may show.
	for _, tc := range []struct{ kind, title, body, want, message string }{
		{"question", "Which branch?", "1. main", "question", "Which branch?"},
		{"approval", "Allow bash?", "rm -rf build", "approval", "Allow bash?"},
		{"prompt", "", "fix the build", "working", ""},
		{"session_start", "", "", "idle", ""},
	} {
		e := base
		e.Session, e.Kind, e.Title, e.Body = "s-b", tc.kind, tc.title, tc.body
		snap := trackedSnapshot(t, []agentEvent{e}, now)
		if snap[0].State != tc.want || snap[0].Message != tc.message {
			t.Fatalf("%s: %+v", tc.kind, snap[0])
		}
	}
}

func TestTrackerInventoryQuestionThenStop(t *testing.T) {
	now := inventoryClock()
	events := []agentEvent{
		{Agent: "codex", Session: "s-c", Mux: "hc", Project: "shinphony", Kind: "prompt"},
		{Agent: "codex", Session: "s-c", Mux: "hc", Project: "shinphony", Kind: "question", Title: "Which branch?", Body: "1. main"},
		{Agent: "codex", Session: "s-c", Mux: "hc", Project: "shinphony", Kind: "stop", Title: "done"},
	}
	snap := trackedSnapshot(t, events, now)
	if snap[0].State != "question" || snap[0].Message != "Which branch?" {
		t.Fatalf("a stop with an open question is still a question: %+v", snap[0])
	}
}

func TestTrackerInventoryDoneDecaysAndFailedSticks(t *testing.T) {
	now := inventoryClock()
	done := []agentEvent{
		{Agent: "codex", Session: "s-d", Mux: "hc", Project: "p", Kind: "prompt"},
		{Agent: "codex", Session: "s-d", Mux: "hc", Project: "p", Kind: "stop", Title: "ok"},
	}
	if snap := trackedSnapshot(t, done, now); snap[0].State != "done" {
		t.Fatalf("state %s", snap[0].State)
	}
	tr := newTracker()
	s := settings{TurnCompletePush: "all", RateLimitPerMinute: 600}
	at := now
	for _, e := range done {
		tr.decide(e, s, at)
		at = at.Add(time.Second)
	}
	if snap := tr.inventoryStates(at.Add(25 * time.Hour)); snap[0].State != "idle" {
		t.Fatalf("done did not decay: %s", snap[0].State)
	}

	failed := []agentEvent{
		{Agent: "codex", Session: "s-e", Mux: "hc", Project: "p", Kind: "prompt"},
		{Agent: "codex", Session: "s-e", Mux: "hc", Project: "p", Kind: "failure", Title: "boom"},
	}
	tr = newTracker()
	at = now
	for _, e := range failed {
		tr.decide(e, s, at)
		at = at.Add(time.Second)
	}
	if snap := tr.inventoryStates(at.Add(48 * time.Hour)); snap[0].State != "failed" {
		t.Fatalf("failed did not stick: %s", snap[0].State)
	}
}

func TestTrackerInventoryRoute(t *testing.T) {
	now := inventoryClock()
	codex := agentEvent{Agent: "codex", Session: "s-f", Mux: "hc", Project: "p", Kind: "prompt",
		Source: &hookSource{Agent: "codex", Thread: "s-f", ParentPID: 42, HcAddress: "t3", HcSocket: "/tmp/hc.sock", HcSession: "default"}}
	snap := trackedSnapshot(t, []agentEvent{codex}, now)
	if snap[0].HcAddress != "t3" || snap[0].HcSession != "default" || snap[0].Mux != "hc" {
		t.Fatalf("%+v", snap[0])
	}
	tmux := agentEvent{Agent: "codex", Session: "s-g", Mux: "tmux", Project: "p", Kind: "prompt",
		Source: &hookSource{Agent: "codex", Thread: "s-g", ParentPID: 42, Tmux: "/tmp/tmux,1,0", Pane: "%9"}}
	if snap = trackedSnapshot(t, []agentEvent{tmux}, now); snap[0].Pane != "%9" || snap[0].TmuxSocket != "/tmp/tmux" {
		t.Fatalf("%+v", snap[0])
	}
}

// ---------------------------------------------------------------------------
// Sources, CLI and the local endpoint.
// ---------------------------------------------------------------------------

// A multiplexer with nothing to list is not a broken source.
func TestInventoryEmptySourcesAreNotErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stdout map[string][]byte
		stderr map[string][]byte
		fail   map[string]bool
	}{
		{"tmux-3.5-no-target", nil, map[string][]byte{"tmux": []byte("no current target\n")}, map[string]bool{"tmux": true}},
		{"tmux-no-server", nil, map[string][]byte{"tmux": []byte("no server running on /tmp/tmux-501/default\n")}, map[string]bool{"tmux": true}},
		{"screen-no-sockets", map[string][]byte{"screen": []byte("No Sockets found in /var/folders/x/T/.screen.\n")}, nil, map[string]bool{"screen": true}},
		{"zellij-no-sessions", map[string][]byte{"zellij": []byte("No active zellij sessions\n")}, nil, map[string]bool{"zellij": true}},
	} {
		sources := inventoryFixtureSources{stdout: tc.stdout, stderr: tc.stderr, fail: tc.fail}
		inv := buildInventory(context.Background(), sources.options())
		if len(inv.Errors) != 0 || len(inv.Conversations) != 0 {
			t.Fatalf("%s: %+v", tc.name, inv)
		}
	}
}

func TestInventoryHcListing(t *testing.T) {
	socket, f := fakeHcListCore(t)
	env := func(key string) string {
		if key == "HC_SOCKET" {
			return socket
		}
		if key == "HC_SESSION" {
			return "default"
		}
		return ""
	}
	listing, err := hcInventoryTerminals(context.Background(), env, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if listing.Session != "default" || len(listing.Terminals) != 2 {
		t.Fatalf("%+v", listing)
	}
	if listing.Terminals[0].Address != "t1" || listing.Terminals[0].StatusMS != 1794755095226 {
		t.Fatalf("%+v", listing.Terminals[0])
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, call := range f.calls {
		if call != "hello" && call != "terminal.list" {
			t.Fatalf("called %s", call)
		}
	}
}

func TestInventoryHcRemoteRowsAreDropped(t *testing.T) {
	sources := inventoryFixtureSources{
		hc: hcListing{Session: "default", Terminals: []hcTerminal{
			hcRow("t1", "local", "", "codex", "working", "/tmp", "", 1000, inventoryNow*1000-1000),
			hcRow("otherhost/t7", "remote", "", "codex", "working", "/home/me", "", 1000, inventoryNow*1000-1000),
		}},
	}
	if got := len(buildInventory(context.Background(), sources.options()).Conversations); got != 1 {
		t.Fatalf("got %d rows", got)
	}
}

func TestInventoryEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	registerInventory(mux, func(context.Context) inventory {
		return inventory{Schema: 1, GeneratedAt: inventoryNow, Conversations: []inventoryConversation{}, Errors: []string{}}
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/inventory", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var inv inventory
	if err := json.Unmarshal(rec.Body.Bytes(), &inv); err != nil || inv.Schema != 1 {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
}

// The CLI must print exactly what the daemon answered: the daemon is the only
// process that still holds in-memory agent state.
func TestInventoryCLIUsesDaemon(t *testing.T) {
	dir := t.TempDir()
	ln, err := listenLocal(dir)
	if err != nil {
		t.Skip("no local socket here:", err)
	}
	mux := http.NewServeMux()
	registerInventory(mux, func(context.Context) inventory {
		agent := "codex"
		return inventory{Schema: 1, GeneratedAt: inventoryNow, Conversations: []inventoryConversation{{
			ID: "c_1111111111111111", Mux: "tmux", Title: "from the daemon", Agent: &agent,
			State: "question", StateSource: "hook", Since: inventoryNow, Route: inventoryRoute{Version: 1, Multiplexer: "tmux"},
		}}, Errors: []string{}}
	})
	server := &http.Server{Handler: mux}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(ln) }()
	defer func() { server.Close(); <-done }()

	var buf bytes.Buffer
	if err = inventoryCLI(dir, &buf); err != nil {
		t.Fatal(err)
	}
	var got inventory
	if err = json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	if len(got.Conversations) != 1 || got.Conversations[0].Title != "from the daemon" {
		t.Fatalf("cli did not print the daemon's answer: %s", buf.String())
	}
}

func TestInventoryDaemonUnavailable(t *testing.T) {
	if _, err := fetchInventory(context.Background(), t.TempDir()); err == nil {
		t.Fatal("a state directory without a daemon must fail")
	}
}

// fakeHcListCore answers hello + terminal.list with a fixed terminal table. It
// is separate from fakeHcCore (hc_context_test.go) because the inventory reads
// the list, never a single terminal.
type fakeHcInventoryCore struct {
	mu    sync.Mutex
	calls []string
	raw   string
	rows  []hcTerminal
}

func fakeHcListCore(t *testing.T) (string, *fakeHcInventoryCore) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket fixture")
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeHcInventoryCore{rows: []hcTerminal{
		{Address: "t1", Name: "claude-main", State: "live", CreatedMS: 1794755086487, PID: 4242, Cwd: "/Users/me/repos/shinphony", StatusMS: 1794755095226,
			Labels: map[string]any{"where": "Shinphony / 1"}, Status: map[string]any{"app": "claude-code", "state": "working"}},
		{Address: "t2", Parent: "t1", State: "live", CreatedMS: 1794755087000, PID: 4243, Cwd: "/Users/me/repos/shinphony",
			Status: map[string]any{"app": "codex", "state": "idle"}},
	}}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				scanner := bufio.NewScanner(conn)
				for scanner.Scan() {
					var req struct {
						ID     int    `json:"id"`
						Method string `json:"method"`
					}
					if json.Unmarshal(scanner.Bytes(), &req) != nil {
						return
					}
					f.mu.Lock()
					f.calls = append(f.calls, req.Method)
					raw := f.raw
					var result any
					switch req.Method {
					case "hello":
						result = map[string]any{"generation": 1, "core": map[string]string{"id": "core-a"},
							"methods": []string{"terminal.get", "terminal.list", "terminal.attach"}}
					case "terminal.list":
						result = map[string]any{"terminals": f.rows, "hidden_finished": 3}
					}
					f.mu.Unlock()
					if raw != "" {
						conn.Write([]byte(raw))
						return
					}
					if result == nil {
						json.NewEncoder(conn).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32000, "message": "unknown_method"}})
						continue
					}
					json.NewEncoder(conn).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
				}
			}()
		}
	}()
	return socket, f
}

func itoa(v int) string { return strconv.Itoa(v) }
