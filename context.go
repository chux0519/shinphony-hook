package main

// Task context is local-first. Task notifications include bounded terminal text.
// The network projection never contains socket paths or PIDs.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type hookSource struct {
	HcAddress string `json:"hcAddress,omitempty"`
	HcSocket  string `json:"hcSocket,omitempty"`
	HcSession string `json:"hcSession,omitempty"`
	Agent     string `json:"agent"`
	Thread    string `json:"thread"`
	ParentPID int    `json:"parentPid"`
	Tmux      string `json:"tmux,omitempty"`
	Pane      string `json:"pane,omitempty"`
	CodexHome string `json:"codexHome,omitempty"`
}
type taskContext struct {
	Version     int    `json:"version"`
	Agent       string `json:"agent"`
	Thread      string `json:"thread"`
	Title       string `json:"title"`
	Multiplexer string `json:"multiplexer"`
	Session     string `json:"session"`
	Window      string `json:"window"`
	Preview     string `json:"preview,omitempty"`
	// Route is an event ID resolved by the daemon, never a command from a push.
	Route  string `json:"route"`
	Binary string `json:"binary"`
	// The conversation an hc helper belongs to, and its space. Empty outside hc
	// and whenever the parent is missing, so the projection stays unchanged.
	Parent      string `json:"parent,omitempty"`
	ParentTitle string `json:"parentTitle,omitempty"`
	Space       string `json:"space,omitempty"`
}
type localSnapshot struct {
	Hc *hcTarget `json:"hc,omitempty"`
	// TerminalOnly marks a resolve-event reply that identifies a terminal only:
	// the agent that created the event is gone, so Route and Binary are cleared
	// and a client must attach to the terminal instead of replaying the event.
	TerminalOnly bool `json:"terminalOnly,omitempty"`
	taskContext
	Socket     string `json:"socket"`
	ServerPID  string `json:"serverPid"`
	SessionID  string `json:"sessionId"`
	WindowID   string `json:"windowId"`
	PaneID     string `json:"paneId"`
	PanePID    string `json:"panePid"`
	AgentPID   int    `json:"agentPid"`
	AgentStart string `json:"agentStart"`
}
type taskContextKey struct{}

func cleanText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		if r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
			return -1
		}
		return r
	}, s)
	if len(s) > limit {
		s = s[:limit]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return strings.TrimSpace(s)
}
func cleanLabel(s string, limit int) string {
	return strings.ReplaceAll(strings.ReplaceAll(cleanText(s, limit), "\n", " "), "\t", " ")
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("output_limit")
	}
	return b.Buffer.Write(p)
}
func commandOutput(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out := &cappedBuffer{limit: 32768}
	cmd.Stdout = out
	cmd.WaitDelay = 100 * time.Millisecond
	err := cmd.Run()
	return out.String(), err
}
func tmuxExecutable() string {
	if p, err := exec.LookPath("tmux"); err == nil {
		return p
	}
	for _, p := range []string{"/opt/homebrew/bin/tmux", "/usr/local/bin/tmux", "/usr/bin/tmux"} {
		if i, e := os.Stat(p); e == nil && !i.IsDir() {
			return p
		}
	}
	return "tmux"
}

// launchd/systemd may omit LANG or set LC_ALL=C. tmux otherwise sanitizes
// format output (including tab delimiters) into underscores. Force its UTF-8
// output mode, without relying on installed locales or changing host settings.
func tmuxOutput(ctx context.Context, args ...string) (string, error) {
	return commandOutput(ctx, tmuxExecutable(), append([]string{"-u"}, args...)...)
}
func processUnderPane(ctx context.Context, pid int, pane string) bool {
	target, e := strconv.Atoi(pane)
	if e != nil || target <= 1 {
		return false
	}
	seen := map[int]bool{}
	for n := 0; n < 24 && pid > 1; n++ {
		if pid == target {
			return true
		}
		if seen[pid] {
			return false
		}
		seen[pid] = true
		pid = processParent(ctx, pid)
	}
	return false
}
func codexTitle(home, thread string) string {
	if home == "" {
		h, _ := os.UserHomeDir()
		home = filepath.Join(h, ".codex")
	}
	if !filepath.IsAbs(home) {
		return ""
	}
	// Read only the bounded tail of the title index, never conversation transcripts.
	path := filepath.Join(home, "session_index.jsonl")
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() {
		return ""
	}
	f, e := os.Open(path)
	if e != nil {
		return ""
	}
	defer f.Close()
	start := max(int64(0), i.Size()-262144)
	if _, e = f.Seek(start, io.SeekStart); e != nil {
		return ""
	}
	b, e := io.ReadAll(io.LimitReader(f, 262144))
	if e != nil {
		return ""
	}
	lines := bytes.Split(b, []byte{'\n'})
	for n := len(lines) - 1; n >= 0; n-- {
		var row struct {
			ID   string `json:"id"`
			Name string `json:"thread_name"`
		}
		if json.Unmarshal(lines[n], &row) == nil && row.ID == thread {
			return cleanLabel(row.Name, 120)
		}
	}
	return ""
}
func captureContext(parent context.Context, s *hookSource, event, dir string) *localSnapshot {
	if s == nil || s.Agent != "codex" || !identifier.MatchString(s.Thread) {
		return nil
	}
	if s.HcAddress != "" || s.HcSocket != "" {
		exe, e := os.Executable()
		if e != nil {
			return nil
		}
		binary, ok := managedBinaryDigest(exe)
		if !ok {
			return nil
		}
		return boundedHcContext(parent, s, event, binary)
	}
	if !regexp.MustCompile(`^%[0-9]+$`).MatchString(s.Pane) {
		return nil
	}
	// TMUX is socket,pid,index. Split from the right because a socket path may contain commas.
	parts := strings.Split(s.Tmux, ",")
	if len(parts) < 3 {
		return nil
	}
	socket := strings.Join(parts[:len(parts)-2], ",")
	if !filepath.IsAbs(socket) || len(socket) > 1024 {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, 1200*time.Millisecond)
	defer cancel()
	run := func(args ...string) (string, error) {
		return tmuxOutput(ctx, append([]string{"-S", socket}, args...)...)
	}
	raw, e := run("display-message", "-p", "-t", s.Pane, "#{pid}\t#{session_id}\t#{window_id}\t#{pane_id}\t#{pane_pid}\t#{session_name}\t#{window_name}")
	if e != nil {
		return nil
	}
	p := strings.Split(strings.TrimSuffix(raw, "\n"), "\t")
	if len(p) != 7 || p[3] != s.Pane {
		return nil
	}
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(p[0]) || !regexp.MustCompile(`^\$[0-9]+$`).MatchString(p[1]) || !regexp.MustCompile(`^@[0-9]+$`).MatchString(p[2]) {
		return nil
	}
	if !processUnderPane(ctx, s.ParentPID, p[4]) {
		return nil
	}
	started := processStart(ctx, s.ParentPID)
	if started == "" {
		return nil
	}
	exe, e := os.Executable()
	if e != nil {
		return nil
	}
	binary, ok := managedBinaryDigest(exe)
	if !ok {
		return nil
	}
	title := codexTitle(s.CodexHome, s.Thread)
	if title == "" {
		title = "Codex · " + s.Thread[:min(8, len(s.Thread))]
	}
	c := &localSnapshot{taskContext: taskContext{Version: 1, Agent: s.Agent, Thread: s.Thread, Title: title, Multiplexer: "tmux", Session: cleanLabel(p[5], 80), Window: cleanLabel(p[6], 80), Route: event, Binary: binary}, Socket: socket, ServerPID: p[0], SessionID: p[1], WindowID: p[2], PaneID: p[3], PanePID: p[4], AgentPID: s.ParentPID, AgentStart: started}
	if text, e := run("capture-pane", "-p", "-J", "-t", s.Pane, "-S", "-8"); e == nil {
		lines := strings.Split(strings.TrimSpace(text), "\n")
		lines = lines[max(0, len(lines)-6):]
		c.Preview = cleanText(strings.Join(lines, "\n"), 700)
	}
	return c
}
func (q *queue) initContexts() error {
	_, e := q.db.Exec(`CREATE TABLE IF NOT EXISTS task_contexts(route_key TEXT PRIMARY KEY, snapshot TEXT NOT NULL, updated INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS task_context_events(event_id TEXT PRIMARY KEY, route_key TEXT NOT NULL, thread TEXT NOT NULL, updated INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS hc_presence(profile TEXT PRIMARY KEY, target TEXT NOT NULL, expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS task_presence(profile TEXT PRIMARY KEY, tty TEXT NOT NULL, expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS recent_sessions(profile TEXT PRIMARY KEY, snapshot TEXT NOT NULL, updated INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS workspace_paths(id TEXT PRIMARY KEY, files TEXT NOT NULL, git TEXT NOT NULL, updated INTEGER NOT NULL);`)
	return e
}
func (q *queue) saveContext(c *localSnapshot, now int64) error {
	route := snapshotRouteKey(c)
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	tx, e := q.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, table := range []string{"task_contexts", "task_context_events"} {
		if _, e = tx.Exec("DELETE FROM "+table+" WHERE updated<?", now-86400); e != nil {
			return e
		}
	}
	if _, e = tx.Exec("INSERT INTO task_contexts VALUES(?,?,?) ON CONFLICT(route_key) DO UPDATE SET snapshot=excluded.snapshot,updated=excluded.updated", route, string(b), now); e != nil {
		return e
	}
	if _, e = tx.Exec("INSERT INTO task_context_events VALUES(?,?,?,?) ON CONFLICT(event_id) DO NOTHING", c.Route, route, c.Thread, now); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM task_contexts WHERE route_key NOT IN (SELECT route_key FROM task_contexts ORDER BY updated DESC LIMIT 128)"); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM task_context_events WHERE event_id NOT IN (SELECT event_id FROM task_context_events ORDER BY updated DESC LIMIT 2000)"); e != nil {
		return e
	}
	return tx.Commit()
}
func (q *queue) contextForEvent(id string) *localSnapshot {
	var raw, thread string
	e := q.db.QueryRow(`SELECT c.snapshot,e.thread FROM task_context_events e JOIN task_contexts c ON c.route_key=e.route_key WHERE e.event_id=? AND c.updated>? AND e.updated>?`, id, time.Now().Unix()-86400, time.Now().Unix()-86400).Scan(&raw, &thread)
	if e != nil {
		return nil
	}
	var c localSnapshot
	if json.Unmarshal([]byte(raw), &c) != nil || c.Thread != thread {
		return nil
	}
	if c.Route != id {
		c.Preview = ""
	} // Never label newer output as an old event.
	c.Route = id
	return &c
}
