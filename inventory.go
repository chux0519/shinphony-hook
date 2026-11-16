package main

// Inventory v1 (design: ShinphonyApp docs/design/agent_first_layout_20261115.md
// §2). `shinphony-hook inventory` prints every conversation on this host — tmux
// windows, hc terminals, zellij and screen sessions — merged with the state the
// agent tracker knows, so the App needs one adapter instead of one per
// multiplexer.
//
// Read-only, always: the listing commands only look, the hc client never starts
// a core, and a source that fails is an error code in the document, never a
// reason to exit non-zero. The daemon serves the same document on the local mux
// at GET /v1/inventory, where it can add the tracker's state; without a daemon
// the CLI prints the mux-only rows.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	inventorySchema = 1
	// maxInventoryConversations bounds a document; the oldest idle rows go first.
	maxInventoryConversations = 200
	// muxActiveSeconds is how recent a multiplexer's last activity must be for a
	// coarse row to say "working". There is no exact time outside the hook. Only
	// herdr's own `blocked` may say "needs you" from a coarse source; tmux output
	// never does.
	muxActiveSeconds = 60
	// doneStateDecay turns a finished turn into quiet after a day, from whichever
	// source says done: the agent's own hook or herdr's own status.
	doneStateDecay = 24 * time.Hour
	// trackedStateFreshness bounds how old a tracker session may be and still be
	// joined to a live row: a stale session must not label somebody else's tab.
	trackedStateFreshness = 24 * time.Hour
	// maxInventoryBytes bounds a daemon reply read by the CLI.
	maxInventoryBytes = 512 * 1024
)

type inventoryGroup struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// inventoryRoute is the tap route of a row: a taskContext, exactly what opening
// or attaching uses. Mux-only rows carry no event, so Route and Binary are empty.
type inventoryRoute struct {
	Version     int    `json:"version"`
	Agent       string `json:"agent"`
	Thread      string `json:"thread"`
	Title       string `json:"title"`
	Multiplexer string `json:"multiplexer"`
	Session     string `json:"session"`
	Window      string `json:"window"`
	Route       string `json:"route"`
	Binary      string `json:"binary"`
	Parent      string `json:"parent,omitempty"`
	ParentTitle string `json:"parentTitle,omitempty"`
	Space       string `json:"space,omitempty"`
}

type inventoryConversation struct {
	ID        string         `json:"id"`
	Mux       string         `json:"mux"`
	Group     inventoryGroup `json:"group"`
	Title     string         `json:"title"`
	Directory string         `json:"directory"`
	Agent     *string        `json:"agent"`
	// Kind is "agent" when a conversation carries an agent identity and "shell"
	// when it is a plain terminal. It is exactly `agent != null`, spelled out so
	// the App can group shells without inferring the rule (schema stays 1).
	Kind        string         `json:"kind"`
	State       string         `json:"state"`
	StateSource string         `json:"stateSource"`
	Since       int64          `json:"since"`
	Message     string         `json:"message"`
	Parent      string         `json:"parent,omitempty"`
	Route       inventoryRoute `json:"route"`
}

type inventory struct {
	Schema        int                     `json:"schema"`
	GeneratedAt   int64                   `json:"generatedAt"`
	Host          string                  `json:"host"`
	Conversations []inventoryConversation `json:"conversations"`
	Errors        []string                `json:"errors"`
}

// hcListing is one core's answer: the session its socket belongs to, and every
// terminal it hosts. Terminals of other machines come back too (address
// "otherhost/t7"); the inventory keeps only this host's.
type hcListing struct {
	Session   string
	Terminals []hcTerminal
}

// inventoryOptions is every input the builder reads, injectable so the tests
// never touch real tmux, a real core or the user's sessions.
type inventoryOptions struct {
	Now    time.Time
	Host   string
	Find   func(tool string) string
	Run    func(ctx context.Context, path string, args []string) (stdout, stderr []byte, err error)
	Hc     func(ctx context.Context) (hcListing, error)
	States func(now time.Time) []trackedConversation
}

// inventoryRow is one conversation before ids, limits and sorting.
type inventoryRow struct {
	mux                      string
	groupKind, groupName     string
	title, directory, agent  string
	state, stateSource       string
	message                  string
	since                    int64
	sessionName, windowName  string
	idSession, idWindow      string
	hcSession, tmuxSocket    string
	hcAddress, parentAddress string
	space, parentTitle       string
	pane                     string
}

// tmuxBenignExit are the ways tmux says there is nothing to list; a host
// without sessions must not look broken. tmux 3.5a answers "no current target"
// with no server, older versions "no server running".
var tmuxBenignExit = []string{"no server running", "error connecting to", "no current target", "no current session", "no sessions", "can't find session"}

var (
	tmuxPaneIDRE   = regexp.MustCompile(`^%[0-9]+$`)
	tmuxSessionRE  = regexp.MustCompile(`^\$[0-9]+$`)
	tmuxWindowIDRE = regexp.MustCompile(`^@[0-9]+$`)
	tmuxNumberRE   = regexp.MustCompile(`^[0-9]+$`)
)

// The listing formats. `-u` is added by the caller for the same reason the
// sessions command has it: launchd-like environments may set LC_ALL=C, and tmux
// then replaces non-ASCII names and paths with underscores.
var tmuxInventoryFormat = strings.Join([]string{
	"#{session_name}", "#{session_id}", "#{window_index}", "#{window_name}", "#{window_id}",
	"#{window_activity}", "#{pane_id}", "#{pane_current_path}", "#{pane_current_command}", "#{socket_path}",
}, "\t")

func runInventoryTool(ctx context.Context, path string, args []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	out, errOut := &cappedBuffer{limit: 262144}, &cappedBuffer{limit: 8192}
	cmd.Stdout, cmd.Stderr, cmd.Stdin = out, errOut, nil
	cmd.WaitDelay = 100 * time.Millisecond
	err := cmd.Run()
	return out.Bytes(), errOut.Bytes(), err
}

func buildInventory(ctx context.Context, o inventoryOptions) inventory {
	return buildInventoryWithLimit(ctx, o, maxInventoryConversations)
}

func buildInventoryWithLimit(ctx context.Context, o inventoryOptions, limit int) inventory {
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	inv := inventory{Schema: inventorySchema, GeneratedAt: now.Unix(), Host: o.Host, Conversations: []inventoryConversation{}, Errors: []string{}}
	var rows []inventoryRow
	if o.Hc != nil {
		list, err := o.Hc(ctx)
		if err != nil {
			inv.Errors = append(inv.Errors, "hc_unavailable")
		} else {
			rows = append(rows, hcRows(list, now)...)
		}
	}
	rows = append(rows, tmuxRows(ctx, o, now, &inv)...)
	rows = append(rows, zellijRows(ctx, o, now, &inv)...)
	rows = append(rows, screenRows(ctx, o, now, &inv)...)
	if o.States != nil {
		applyHookStates(rows, o.States(now), now)
	}
	// Parent titles name the conversation a helper belongs to even when that row
	// is dropped below; the parent link itself only points at a row present here.
	titles := map[string]string{}
	for _, r := range rows {
		if r.hcAddress != "" {
			titles[r.hcAddress] = excerpt(r.title, 120, false)
		}
	}
	rows = truncateInventoryRows(rows, limit)
	conversations := make([]inventoryConversation, 0, len(rows))
	for _, r := range rows {
		conversations = append(conversations, r.conversation())
	}
	ids := map[string]string{}
	for i, r := range rows {
		if r.hcAddress != "" {
			ids[r.hcAddress] = conversations[i].ID
		}
	}
	for i, r := range rows {
		// A helper only points at a conversation this document carries: a parent
		// that is gone, dropped by the limit or belongs to another machine is not
		// a route anybody could open.
		id, ok := ids[r.parentAddress]
		if !ok || r.parentAddress == r.hcAddress {
			continue
		}
		conversations[i].Parent = id
		conversations[i].Route.Parent = r.parentAddress
		if title := titles[r.parentAddress]; title != "" {
			conversations[i].Route.ParentTitle = title
		}
	}
	sortConversations(conversations)
	inv.Conversations = conversations
	return inv
}

func (r inventoryRow) conversation() inventoryConversation {
	c := inventoryConversation{
		ID:          conversationID(r.mux, r.idSession, r.idWindow),
		Mux:         r.mux,
		Group:       inventoryGroup{Kind: r.groupKind, Name: excerpt(r.groupName, 80, false)},
		Title:       excerpt(r.title, 120, false),
		Kind:        "shell",
		State:       r.state,
		StateSource: r.stateSource,
		Since:       r.since,
		Message:     excerpt(r.message, 120, false),
		Route: inventoryRoute{Version: 1, Agent: r.agent, Title: excerpt(r.title, 120, false), Multiplexer: r.mux,
			Session: excerpt(r.sessionName, 80, false), Window: excerpt(r.windowName, 80, false), Space: r.space},
	}
	if r.directory != "" && filepath.IsAbs(r.directory) {
		c.Directory = cleanLabel(r.directory, 1024)
	}
	if r.agent != "" {
		agent := r.agent
		c.Agent = &agent
		c.Kind = "agent"
	}
	return c
}

// conversationID is stable for the same conversation across daemon restarts,
// renames and state changes: first 16 hex of sha256(mux, session, window id).
func conversationID(mux, session, window string) string {
	sum := sha256.Sum256([]byte(mux + "\x00" + session + "\x00" + window))
	return "c_" + hex.EncodeToString(sum[:8])
}

// ---------------------------------------------------------------------------
// hc
// ---------------------------------------------------------------------------

func hcInventoryTerminals(ctx context.Context, getenv func(string) string, home string) (hcListing, error) {
	socket, session := hcDebugEndpoint(getenv, home)
	if socket == "" {
		// No core: hc has no conversations here. Not an error, and never a reason
		// to start one.
		return hcListing{}, nil
	}
	rpc, err := openHcRPC(ctx, socket)
	if err != nil {
		return hcListing{}, err
	}
	defer rpc.close()
	if _, err = rpc.hello(); err != nil {
		return hcListing{}, err
	}
	terminals, err := rpc.terminals()
	if err != nil {
		return hcListing{}, err
	}
	return hcListing{Session: session, Terminals: terminals}, nil
}

func hcRows(list hcListing, now time.Time) []inventoryRow {
	var rows []inventoryRow
	seen := map[string]bool{}
	for _, t := range list.Terminals {
		// A remote machine's terminal (address "otherhost/t7") belongs to that
		// machine's own inventory; a finished one is not a conversation.
		if !hcAddressRE.MatchString(t.Address) || t.State != "live" || seen[t.Address] {
			continue
		}
		seen[t.Address] = true
		state, source, message, since := hcRowState(t, now)
		row := inventoryRow{
			mux: "hc", title: hcTitle(t), directory: t.Cwd, agent: agentFromName(hcString(t.Status, "app")),
			state: state, stateSource: source, message: message, since: since,
			sessionName: cleanLabel(t.Name, 80), windowName: t.Address,
			idSession: list.Session, idWindow: t.Address, hcSession: list.Session,
			hcAddress: t.Address, parentAddress: t.Parent, space: hcSpace(t),
			groupKind: "other",
		}
		if row.sessionName == "" {
			row.sessionName = t.Address
		}
		if row.space != "" {
			row.groupKind, row.groupName = "hcSpace", row.space
		}
		rows = append(rows, row)
	}
	return rows
}

// hcRowState maps herdr's own status (herdr_core status: idle, working, done,
// blocked, error) to the inventory's vocabulary at full fidelity. A coarse row
// is what the multiplexer knows, and herdr knows the program's own word, so
// flattening `done` to `idle` hid a finished turn and `blocked` to `idle` hid a
// program waiting for the user.
//
//	| herdr status.state | inventory state          | stateSource |
//	| working            | working                  | mux         |
//	| done               | done, idle after 24 h    | mux         |
//	| idle               | idle                     | mux         |
//	| blocked            | question + status.msg    | mux         |
//	| error              | failed                   | mux         |
//	| any other word     | activity (60 s) of it    | mux         |
//	| no status at all   | unknown for an agent,    | none        |
//	|                    | idle for a plain shell   |             |
//
// `blocked` is the only "needs you" a coarse row may say — the App's own
// convention, and herdr says it only when the program asked something
// (status.kind: permission, question or auth). `approval` stays hook-only.
func hcRowState(t hcTerminal, now time.Time) (state, source, message string, since int64) {
	since = now.Unix()
	if t.StatusMS > 0 {
		since = t.StatusMS / 1000
	} else if t.CreatedMS > 0 {
		since = t.CreatedMS / 1000
	}
	switch word := hcString(t.Status, "state"); word {
	case "working":
		return "working", "mux", "", since
	case "done":
		return settledDone(now, since), "mux", "", since
	case "idle":
		return "idle", "mux", "", since
	case "blocked":
		return "question", "mux", excerpt(hcString(t.Status, "msg"), 120, false), since
	case "error":
		return "failed", "mux", "", since
	case "":
		// Nothing was reported: an agent we recognise has told us nothing yet, a
		// plain shell is quiet. Never "working" — herdr said nothing of the kind.
		if agentFromName(hcString(t.Status, "app")) == "" {
			return "idle", "none", "", since
		}
		return "unknown", "none", "", since
	}
	// A word this build does not know (a newer herdr): fall back to the coarse
	// activity of the status change instead of inventing a state.
	return activityState(now, since), "mux", "", since
}

// settledDone is done for a day and quiet afterwards, on the clock of whichever
// source said done.
func settledDone(now time.Time, since int64) string {
	if since > 0 && now.Unix()-since >= int64(doneStateDecay/time.Second) {
		return "idle"
	}
	return "done"
}

func activityState(now time.Time, since int64) string {
	if since <= 0 {
		return "unknown"
	}
	if now.Unix()-since <= muxActiveSeconds {
		return "working"
	}
	return "idle"
}

// agentFromName maps the program or app identity to the inventory's agent
// vocabulary. It never guesses: "node" could be anything, so it stays null.
func agentFromName(name string) string {
	switch strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".exe")) {
	case "claude", "claude-code":
		return "claude"
	case "codex":
		return "codex"
	case "agy", "antigravity":
		return "agy"
	case "dsh":
		return "dsh"
	case "pi":
		return "pi"
	}
	return ""
}

// ---------------------------------------------------------------------------
// tmux, zellij, screen
// ---------------------------------------------------------------------------

func tmuxRows(ctx context.Context, o inventoryOptions, now time.Time, inv *inventory) []inventoryRow {
	path := ""
	if o.Find != nil {
		path = o.Find("tmux")
	}
	if path == "" || o.Run == nil {
		return nil
	}
	out, stderr, err := o.Run(ctx, path, []string{"-u", "list-windows", "-a", "-F", tmuxInventoryFormat})
	if err != nil {
		// A host without sessions is not a broken source: tmux says so on stderr
		// and exits non-zero.
		for _, benign := range tmuxBenignExit {
			if strings.Contains(string(stderr), benign) {
				return nil
			}
		}
		inv.Errors = append(inv.Errors, "tmux_unavailable")
		return nil
	}
	return parseTmuxWindows(out, now)
}

func parseTmuxWindows(raw []byte, now time.Time) []inventoryRow {
	var rows []inventoryRow
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 10 {
			continue
		}
		session, sessionID, windowName, windowID := f[0], f[1], f[3], f[4]
		activity, pane, cwd, command, socket := f[5], f[6], f[7], f[8], f[9]
		if session == "" || !tmuxSessionRE.MatchString(sessionID) || !tmuxNumberRE.MatchString(f[2]) || !tmuxWindowIDRE.MatchString(windowID) || !tmuxPaneIDRE.MatchString(pane) {
			continue
		}
		since, err := strconv.ParseInt(activity, 10, 64)
		if err != nil || since <= 0 {
			since = now.Unix()
		}
		title := windowName
		if title == "" {
			title = session
		}
		agent := agentFromName(command)
		state, source := activityState(now, since), "mux"
		if agent == "" {
			// A foreground program that is not an agent is a shell: output proves
			// something ran, not that an agent is working. Quiet, and with no state
			// source, until a hook says otherwise (a hook then sets the agent too).
			state, source = "idle", "none"
		}
		rows = append(rows, inventoryRow{
			mux: "tmux", groupKind: "tmuxSession", groupName: session,
			title: title, directory: cwd, agent: agent,
			state: state, stateSource: source, since: since,
			sessionName: session, windowName: windowName,
			idSession: sessionID, idWindow: windowID,
			pane: pane, tmuxSocket: socket,
		})
	}
	return rows
}

func zellijRows(ctx context.Context, o inventoryOptions, now time.Time, inv *inventory) []inventoryRow {
	path := ""
	if o.Find != nil {
		path = o.Find("zellij")
	}
	if path == "" || o.Run == nil {
		return nil
	}
	out, _, err := o.Run(ctx, path, []string{"list-sessions", "--no-formatting"})
	if err != nil && !strings.Contains(string(out), "No active") {
		inv.Errors = append(inv.Errors, "zellij_unavailable")
		return nil
	}
	var rows []inventoryRow
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name == "" || strings.HasPrefix(name, "No ") {
			continue
		}
		rows = append(rows, zellijRow("zellij", name, now))
	}
	return rows
}

func screenRows(ctx context.Context, o inventoryOptions, now time.Time, inv *inventory) []inventoryRow {
	path := ""
	if o.Find != nil {
		path = o.Find("screen")
	}
	if path == "" || o.Run == nil {
		return nil
	}
	out, _, err := o.Run(ctx, path, []string{"-ls"})
	if err != nil && !strings.Contains(string(out), "No Sockets found") {
		inv.Errors = append(inv.Errors, "screen_unavailable")
		return nil
	}
	var rows []inventoryRow
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "(") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// "12345.pts-0.host (Detached)": the number is screen's pid, the name
		// follows the first dot.
		name := fields[0]
		if i := strings.Index(name, "."); i >= 0 && i+1 < len(name) {
			name = name[i+1:]
		}
		rows = append(rows, zellijRow("shell", name, now))
	}
	return rows
}

// zellijRow is a plain row: the multiplexer proves a shell exists and nothing
// about what runs in it, so it is quiet rather than unknown-or-working.
func zellijRow(mux, name string, now time.Time) inventoryRow {
	return inventoryRow{
		mux: mux, groupKind: "other", title: name,
		state: "idle", stateSource: "none", since: now.Unix(),
		sessionName: name, idSession: name,
	}
}

// ---------------------------------------------------------------------------
// Merge, limits, order
// ---------------------------------------------------------------------------

// routeKey is the conversation a route names, in one place: the tracker's
// snapshot and the inventory's rows must agree on it or a state joins nothing.
// A route without a terminal or pane identity names nothing (that event may only
// use the project fallback).
func routeKey(hcSession, hcAddress, tmuxSocket, pane string) string {
	if hcAddress != "" {
		return "hc\x00" + hcSession + "\x00" + hcAddress
	}
	if pane != "" {
		return "tmux\x00" + tmuxSocket + "\x00" + pane
	}
	return ""
}

// applyHookStates joins the tracker's state to the mux rows. An exact route (an
// hc terminal or a tmux pane the event named) always wins. Only a state that
// carries no route facts may fall back to a unique (agent, project) match, and
// only when that match is unique in both directions: two tabs in one folder, or
// two tracked sessions, prove nothing and leave the coarse mux state alone.
func applyHookStates(rows []inventoryRow, states []trackedConversation, now time.Time) {
	fresh := func(s trackedConversation) bool {
		return s.Seen > 0 && s.State != "" && now.Unix()-s.Seen <= int64(trackedStateFreshness/time.Second)
	}
	exact := func(r inventoryRow, s trackedConversation) bool {
		if s.HcAddress != "" {
			// The same address exists in every core session, so the session the
			// event named is part of the identity when both sides know it.
			return r.mux == "hc" && r.hcAddress == s.HcAddress && (s.HcSession == "" || s.HcSession == r.hcSession)
		}
		if s.Pane != "" {
			// Pane ids repeat across tmux servers (sockets).
			return r.mux == "tmux" && r.pane == s.Pane && (s.TmuxSocket == "" || s.TmuxSocket == r.tmuxSocket)
		}
		return false
	}
	project := func(r inventoryRow, s trackedConversation) bool {
		// A route is an identity, not a hint: an event that named a pane or a
		// terminal is never re-attributed to another row in the same folder.
		if s.HcAddress != "" || s.Pane != "" {
			return false
		}
		if s.Project == "" || r.directory == "" || r.stateSource == "hook" {
			return false
		}
		if s.Agent == "" || (r.agent != "" && r.agent != s.Agent) {
			return false
		}
		if s.Mux != "" && s.Mux != r.mux {
			return false
		}
		// A named session or socket that is not this row's is evidence of a
		// different server, not merely a missing match.
		if s.HcSession != "" && r.mux == "hc" && s.HcSession != r.hcSession {
			return false
		}
		if s.TmuxSocket != "" && r.mux == "tmux" && s.TmuxSocket != r.tmuxSocket {
			return false
		}
		return filepath.Base(r.directory) == s.Project
	}
	usedRow := make([]bool, len(rows))
	usedState := make([]bool, len(states))
	apply := func(r *inventoryRow, s trackedConversation) {
		r.state, r.stateSource, r.message, r.since = s.State, "hook", s.Message, s.Since
		if r.agent == "" {
			r.agent = s.Agent
		}
	}
	// Exact routes first. A pane or terminal hosts one agent at a time, so when
	// more than one tracked session names the same row (a partial identity, or a
	// session the agent never ended) the one seen last is the occupant.
	for j := range rows {
		best := -1
		for i, s := range states {
			if usedState[i] || !fresh(s) || !exact(rows[j], s) {
				continue
			}
			if best < 0 || s.Seen > states[best].Seen {
				best = i
			}
		}
		if best < 0 {
			continue
		}
		apply(&rows[j], states[best])
		usedRow[j], usedState[best] = true, true
	}
	rowsForState := map[int][]int{}
	statesForRow := map[int][]int{}
	for i, s := range states {
		if usedState[i] || !fresh(s) {
			continue
		}
		for j := range rows {
			if !usedRow[j] && project(rows[j], s) {
				rowsForState[i] = append(rowsForState[i], j)
				statesForRow[j] = append(statesForRow[j], i)
			}
		}
	}
	for j, list := range statesForRow {
		if len(list) != 1 || len(rowsForState[list[0]]) != 1 {
			continue
		}
		apply(&rows[j], states[list[0]])
	}
}

// inventoryStateRank decides what survives truncation: quiet rows first, a row
// that needs the user last.
func inventoryStateRank(state string) int {
	switch state {
	case "idle":
		return 1
	case "done":
		return 2
	case "working":
		return 3
	case "failed":
		return 4
	case "question":
		return 5
	case "approval":
		return 6
	}
	return 0 // unknown
}

func truncateInventoryRows(rows []inventoryRow, limit int) []inventoryRow {
	if limit <= 0 || len(rows) <= limit {
		return rows
	}
	sorted := append([]inventoryRow(nil), rows...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := inventoryStateRank(sorted[i].state), inventoryStateRank(sorted[j].state)
		if ri != rj {
			return ri < rj
		}
		return sorted[i].since < sorted[j].since
	})
	return sorted[len(sorted)-limit:]
}

func muxRank(mux string) int {
	switch mux {
	case "hc":
		return 0
	case "tmux":
		return 1
	case "rex":
		return 2
	case "zellij":
		return 3
	case "shell":
		return 4
	}
	return 5
}

func sortConversations(list []inventoryConversation) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if muxRank(a.Mux) != muxRank(b.Mux) {
			return muxRank(a.Mux) < muxRank(b.Mux)
		}
		if a.Group.Name != b.Group.Name {
			return a.Group.Name < b.Group.Name
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return a.ID < b.ID
	})
}

// ---------------------------------------------------------------------------
// CLI and the local endpoint
// ---------------------------------------------------------------------------

func realInventoryOptions(states func(time.Time) []trackedConversation, now time.Time) inventoryOptions {
	home, _ := os.UserHomeDir()
	return inventoryOptions{
		Now:    now,
		Find:   func(tool string) string { return findTool(tool, exec.LookPath, home) },
		Run:    runInventoryTool,
		Hc:     func(ctx context.Context) (hcListing, error) { return hcInventoryTerminals(ctx, os.Getenv, home) },
		States: states,
	}
}

// inventoryCLI prefers the daemon, which is the only process that still holds
// in-memory agent state; without it the mux rows are still a valid answer.
func inventoryCLI(dir string, w io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if raw, err := fetchInventory(ctx, dir); err == nil {
		_, err = w.Write(raw)
		return err
	}
	return json.NewEncoder(w).Encode(inventoryFallback(ctx, realInventoryOptions(nil, time.Now())))
}

// inventoryFallback is the mux-only document: every row is coarse because the
// daemon (the only process holding the tracker's state) did not answer. The
// document says so, so "every row is stateSource mux" is explainable instead of
// looking like a broken join.
func inventoryFallback(ctx context.Context, o inventoryOptions) inventory {
	inv := buildInventory(ctx, o)
	inv.Errors = append([]string{"daemon_unavailable"}, inv.Errors...)
	return inv
}

func fetchInventory(ctx context.Context, dir string) ([]byte, error) {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost/v1/inventory", nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, errors.New("daemon_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("inventory_unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxInventoryBytes))
	if err != nil {
		return nil, errors.New("inventory_unavailable")
	}
	var inv inventory
	if json.Unmarshal(raw, &inv) != nil || inv.Schema != inventorySchema || inv.Conversations == nil {
		return nil, errors.New("invalid_inventory")
	}
	return raw, nil
}

func registerInventory(mux *http.ServeMux, build func(context.Context) inventory) {
	mux.HandleFunc("GET /v1/inventory", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(build(ctx))
	})
}
