package main

// hc is queried locally over its existing socket/pipe. Discovery never starts a
// core. Agent hooks remain the single notification authority; OSC 7501 is not
// interpreted as an additional task-completion source.
import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type hcTarget struct {
	CoreID    string `json:"coreId"`
	Address   string `json:"address"`
	CreatedMS int64  `json:"createdMs"`
	PID       int    `json:"pid"`
	Socket    string `json:"socket"`
	Session   string `json:"session"`
	// Parent is the topmost live ancestor a helper belongs to, the terminal the
	// app opens for a helper notification. All three are display data: a missing
	// or cyclic parent leaves them empty and the event unchanged.
	Parent      string `json:"parent,omitempty"`
	ParentTitle string `json:"parentTitle,omitempty"`
	Space       string `json:"space,omitempty"`
}
type hcTerminal struct {
	Address   string  `json:"address"`
	Name      string  `json:"name"`
	State     string  `json:"state"`
	Reason    *string `json:"reason"`
	CreatedMS int64   `json:"created_ms"`
	PID       int     `json:"pid"`
	Cwd       string  `json:"cwd"`
	// The remaining fields are display metadata only (title, space, ancestry).
	// They stay untyped so an unexpected shape in one of them can never fail the
	// identity lookup it travels with.
	Parent     string         `json:"parent"`
	Labels     map[string]any `json:"labels"`
	Status     map[string]any `json:"status"`
	Foreground map[string]any `json:"foreground"`
}

var hcAddressRE = regexp.MustCompile(`^t[0-9a-z]{1,32}$`)

const (
	hcParentHops = 3
	hcTitleLimit = 120
	hcSpaceLimit = 80
)

func (t *hcTarget) valid() bool {
	return t != nil && hcAddressRE.MatchString(t.Address) && identifier.MatchString(t.CoreID) && t.CreatedMS > 0 && t.PID > 1 &&
		len(t.Socket) <= 1024 && validHcSocket(t.Socket) && len(t.Session) <= 64 && cleanLabel(t.Session, 64) == t.Session && !strings.ContainsAny(t.Session, "/\\:*?\"<>|\x00\r\n\t") && t.Session != "." && t.Session != ".." &&
		(t.Parent == "" || hcAddressRE.MatchString(t.Parent)) && len(t.ParentTitle) <= hcTitleLimit && cleanLabel(t.ParentTitle, hcTitleLimit) == t.ParentTitle &&
		len(t.Space) <= hcSpaceLimit && cleanLabel(t.Space, hcSpaceLimit) == t.Space
}
func hookSourceFromEnv(agent, thread string, pid int, getenv func(string) string) *hookSource {
	return &hookSource{Agent: agent, Thread: thread, ParentPID: pid, Tmux: getenv("TMUX"), Pane: getenv("TMUX_PANE"), CodexHome: getenv("CODEX_HOME"),
		HcAddress: getenv("HC_TERMINAL_ID"), HcSocket: getenv("HC_TERMINAL_SOCKET"), HcSession: getenv("HC_SESSION")}
}
func hcExecutable() string {
	if p, e := exec.LookPath("hc"); e == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	for _, dir := range []string{filepath.Join(home, ".local", "bin"), filepath.Join(home, ".cargo", "bin")} {
		for _, name := range []string{"hc", "hc.exe"} {
			p := filepath.Join(dir, name)
			if i, e := os.Stat(p); e == nil && !i.IsDir() {
				return p
			}
		}
	}
	return "hc"
}

type hcRPC struct {
	conn  net.Conn
	lines *bufio.Scanner
	next  int
	stop  func() bool
}

func openHcRPC(ctx context.Context, socket string) (*hcRPC, error) {
	if !validHcSocket(socket) || len(socket) > 1024 {
		return nil, errors.New("invalid_hc_socket")
	}
	conn, e := dialHc(ctx, socket)
	if e != nil {
		return nil, e
	}
	deadline := time.Now().Add(1200 * time.Millisecond)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	conn.SetDeadline(deadline)
	r := &hcRPC{conn: conn, lines: bufio.NewScanner(conn)}
	r.lines.Buffer(make([]byte, 4096), 256*1024)
	r.stop = context.AfterFunc(ctx, func() { conn.Close() })
	return r, nil
}
func (r *hcRPC) close() { r.stop(); r.conn.Close() }
func (r *hcRPC) call(method string, params any, result any) error {
	r.next++
	b, e := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": r.next, "method": method, "params": params})
	if e != nil {
		return e
	}
	if _, e = r.conn.Write(append(b, '\n')); e != nil {
		return e
	}
	if !r.lines.Scan() {
		return errors.New("hc_response_unavailable")
	}
	raw := r.lines.Bytes()
	if !utf8.Valid(raw) {
		return errors.New("invalid_hc_utf8")
	}
	var reply struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Error   json.RawMessage `json:"error"`
		Result  json.RawMessage `json:"result"`
	}
	if json.Unmarshal(raw, &reply) != nil || reply.JSONRPC != "2.0" || reply.ID != r.next || (len(reply.Error) > 0 && string(reply.Error) != "null") || len(reply.Result) == 0 {
		return errors.New("invalid_hc_response")
	}
	return json.Unmarshal(reply.Result, result)
}
func (r *hcRPC) hello() (string, error) {
	var h struct {
		Generation int `json:"generation"`
		Core       struct {
			ID string `json:"id"`
		} `json:"core"`
		Methods []string `json:"methods"`
	}
	if e := r.call("hello", map[string]any{"generation": 1, "framed": false}, &h); e != nil {
		return "", e
	}
	methods := map[string]bool{}
	for _, m := range h.Methods {
		methods[m] = true
	}
	if h.Generation != 1 || !identifier.MatchString(h.Core.ID) || !methods["terminal.get"] || !methods["terminal.attach"] {
		return "", errors.New("unsupported_hc_protocol")
	}
	return h.Core.ID, nil
}
func (r *hcRPC) terminal(address string) (hcTerminal, error) {
	var t hcTerminal
	e := r.call("terminal.get", map[string]any{"terminal": address}, &t)
	if e != nil || t.Address != address || t.State != "live" || t.Reason != nil || t.PID <= 1 || t.CreatedMS <= 0 {
		return t, errors.New("hc_target_unavailable")
	}
	return t, nil
}

// A pid belongs to the program the terminal currently runs, and herdr `keep`
// replaces that program while the terminal survives, so the route is keyed by
// the terminal (socket, session, address, created_ms) and the core that hosts
// it. A restart therefore keeps the route of the terminal it restarted.
func snapshotRouteKey(c *localSnapshot) string {
	parts := []string{c.Socket, c.ServerPID, c.PaneID}
	if c.Multiplexer == "hc" && c.Hc != nil {
		t := c.Hc
		parts = []string{"hc", t.Socket, t.Session, t.CoreID, t.Address, strconv.FormatInt(t.CreatedMS, 10)}
	}
	hash := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(hash[:])
}
func captureHcContext(ctx context.Context, s *hookSource, event, binary string) *localSnapshot {
	// An hc environment wins over inherited TMUX. Invalid hc identity fails closed
	// rather than sending a nested terminal to an unrelated outer tmux pane.
	return captureHcSnapshot(ctx, s, event, binary, true)
}

// captureHcSnapshot reads one terminal and its conversation from an already
// running core. requireAgent is false only for the read-only debug command: an
// event is always created by an agent that is verifiably running under the
// terminal, and that check stays here so no caller can skip it by accident.
func captureHcSnapshot(ctx context.Context, s *hookSource, event, binary string, requireAgent bool) *localSnapshot {
	if !hcAddressRE.MatchString(s.HcAddress) || !validHcSocket(s.HcSocket) {
		return nil
	}
	rpc, e := openHcRPC(ctx, s.HcSocket)
	if e != nil {
		return nil
	}
	defer rpc.close()
	core, e := rpc.hello()
	if e != nil {
		return nil
	}
	t, e := rpc.terminal(s.HcAddress)
	if e != nil {
		return nil
	}
	if requireAgent && !processUnderPane(ctx, s.ParentPID, strconv.Itoa(t.PID)) {
		return nil
	}
	started := ""
	if requireAgent {
		if started = processStart(ctx, s.ParentPID); started == "" {
			return nil
		}
	}
	target := &hcTarget{CoreID: core, Address: t.Address, CreatedMS: t.CreatedMS, PID: t.PID, Socket: s.HcSocket, Session: s.HcSession,
		Space: hcSpace(t)}
	if !target.valid() {
		return nil
	}
	// One more read inside the same capture budget. A slow, missing or cyclic
	// parent only omits the conversation; it never fails or delays this event
	// beyond the deadline already set on the connection.
	target.Parent, target.ParentTitle = hcParent(rpc, t)
	title := codexTitle(s.CodexHome, s.Thread)
	if title == "" {
		title = "Codex · " + s.Thread[:min(8, len(s.Thread))]
	}
	label := cleanLabel(t.Name, 80)
	if label == "" {
		label = t.Address
	}
	// Never use terminal.read here: it may scroll a foreground alternate-screen
	// application. Native hook excerpts already supply bounded reply text.
	return &localSnapshot{taskContext: taskContext{Version: 1, Agent: s.Agent, Thread: s.Thread, Title: title, Multiplexer: "hc", Session: label, Window: t.Address, Route: event, Binary: binary,
		Parent: target.Parent, ParentTitle: target.ParentTitle, Space: target.Space}, Hc: target, AgentPID: s.ParentPID, AgentStart: started}
}
func validateHcContext(ctx context.Context, c *localSnapshot) error {
	if c == nil || c.Multiplexer != "hc" || !c.Hc.valid() {
		return errors.New("unsupported_target")
	}
	rpc, e := openHcRPC(ctx, c.Hc.Socket)
	if e != nil {
		return errors.New("target_unavailable")
	}
	defer rpc.close()
	// The core id is not part of the terminal: a core restart reloads the same
	// persisted registry. It is checked only for a protocol-valid hello.
	if _, e = rpc.hello(); e != nil {
		return errors.New("target_exited_or_replaced")
	}
	t, e := rpc.terminal(c.Hc.Address)
	if e != nil {
		return errors.New("target_exited_or_replaced")
	}
	// Same session, address and created_ms is the same terminal even when the
	// program pid changed (herdr `keep` restart). A recreated terminal has a new
	// created_ms and is rejected. The security property is unchanged: the agent
	// that reported must still be a live process under the terminal's current
	// program pid, with an unchanged start time.
	if t.CreatedMS != c.Hc.CreatedMS || processStart(ctx, c.AgentPID) != c.AgentStart || !processUnderPane(ctx, c.AgentPID, strconv.Itoa(t.PID)) {
		return errors.New("target_exited_or_replaced")
	}
	return nil
}

// hcTerminalOnlyRoute accepts the same terminal (session + address +
// created_ms) without requiring the agent that reported the event to still be
// alive. A tap after the helper exited must still open the terminal it names.
// Capture and attach-event keep the strict agent check: this is only the
// identity half of a route.
func hcTerminalOnlyRoute(ctx context.Context, c *localSnapshot) error {
	if c == nil || c.Multiplexer != "hc" || !c.Hc.valid() {
		return errors.New("unsupported_target")
	}
	rpc, e := openHcRPC(ctx, c.Hc.Socket)
	if e != nil {
		return errors.New("target_unavailable")
	}
	defer rpc.close()
	if _, e = rpc.hello(); e != nil {
		return errors.New("target_exited_or_replaced")
	}
	t, e := rpc.terminal(c.Hc.Address)
	if e != nil || t.CreatedMS != c.Hc.CreatedMS {
		return errors.New("target_exited_or_replaced")
	}
	return nil
}

// resolveHcEvent is what `resolve-event` prints. The strict check runs first, so
// an event whose agent is alive keeps its one-shot route. Otherwise the same
// terminal resolves as a terminal-only route: TerminalOnly is set and Route and
// Binary are cleared, so a client attaches to the terminal instead of replaying
// an event it can no longer validate. Any terminal mismatch returns the strict
// error, and the caller keeps its existing fallback.
func resolveHcEvent(ctx context.Context, c *localSnapshot) (localSnapshot, error) {
	if c == nil {
		return localSnapshot{}, errors.New("invalid_context")
	}
	if c.Multiplexer != "hc" {
		return *c, nil
	}
	strict := validateHcContext(ctx, c)
	if strict == nil {
		return *c, nil
	}
	if hcTerminalOnlyRoute(ctx, c) != nil {
		return localSnapshot{}, strict
	}
	out := *c
	out.TerminalOnly = true
	out.Route, out.Binary = "", ""
	return out, nil
}

// hcParent follows `parent` to the topmost live ancestor the app would open for
// a helper, at most three hops and guarded against cycles. A dead or missing
// ancestor keeps the last live one; no ancestor leaves both empty.
func hcParent(rpc *hcRPC, t hcTerminal) (parent, title string) {
	seen := map[string]bool{t.Address: true}
	for hop := 0; hop < hcParentHops; hop++ {
		address := t.Parent
		if !hcAddressRE.MatchString(address) || seen[address] {
			return parent, title
		}
		seen[address] = true
		row, e := rpc.terminal(address)
		if e != nil {
			return parent, title
		}
		parent, title, t = address, hcTitle(row), row
	}
	return parent, title
}

// hcTitle builds a conversation title the same way the app builds an hc tab:
// an explicit name, then app label and space, then program and folder, then the
// address. hcSpace is the space half of `labels.where` ("<space> / <tab>").
func hcTitle(t hcTerminal) string {
	if name := cleanLabel(t.Name, hcTitleLimit); name != "" {
		return name
	}
	space := hcSpace(t)
	if app := hcAppLabel(hcString(t.Status, "app")); app != "" {
		if space == "" {
			return app
		}
		return cleanLabel(app+" — "+space, hcTitleLimit)
	}
	program := hcProgramName(t.Foreground)
	folder := hcFolderLabel(t.Foreground, t.Cwd)
	if program != "" {
		if folder == "" {
			return program
		}
		return cleanLabel(program+" · "+folder, hcTitleLimit)
	}
	if folder != "" {
		return folder
	}
	return t.Address
}
func hcAppLabel(value string) string {
	label := cleanLabel(value, 128)
	switch strings.ToLower(label) {
	case "claude-code", "claude":
		return "Claude Code"
	}
	return label
}
func hcSpace(t hcTerminal) string {
	where := hcString(t.Labels, "where")
	// The space name may contain a slash, so split at the last separator.
	if i := strings.LastIndex(where, " / "); i > 0 {
		where = where[:i]
	}
	return cleanLabel(where, hcSpaceLimit)
}
func hcString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
func hcProgramName(foreground map[string]any) string {
	if argv, ok := foreground["argv"].([]any); ok && len(argv) > 0 {
		if first, ok := argv[0].(string); ok {
			path := strings.ReplaceAll(first, "\\", "/")
			if base := cleanLabel(path[strings.LastIndex(path, "/")+1:], 80); base != "" {
				return base
			}
		}
	}
	return cleanLabel(hcString(foreground, "name"), 80)
}
func hcFolderLabel(foreground map[string]any, cwd string) string {
	directory := hcString(foreground, "cwd")
	if directory == "" {
		directory = cwd
	}
	parts := strings.FieldsFunc(directory, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) == 0 {
		return cleanLabel(directory, 80)
	}
	return cleanLabel(parts[len(parts)-1], 80)
}
func attachHcContext(ctx context.Context, c *localSnapshot) error {
	if e := validateHcContext(ctx, c); e != nil {
		return e
	}
	// exec's environment is supplied explicitly; untrusted push fields never
	// become shell text, executable paths, or environment assignments.
	env := append([]string{}, os.Environ()...)
	env = setEnv(env, "HC_SOCKET", c.Hc.Socket)
	env = setEnv(env, "HC_SESSION", c.Hc.Session)
	return execAttachEnv(hcExecutable(), []string{"attach", "--history", "1000", c.Hc.Address}, env)
}
func setEnv(env []string, key, value string) []string {
	out := []string{}
	for _, v := range env {
		if !strings.HasPrefix(v, key+"=") {
			out = append(out, v)
		}
	}
	return append(out, fmt.Sprintf("%s=%s", key, value))
}

func boundedHcContext(parent context.Context, s *hookSource, event, binary string) *localSnapshot {
	ctx, cancel := context.WithTimeout(parent, 1200*time.Millisecond)
	defer cancel()
	return captureHcContext(ctx, s, event, binary)
}

// Native hooks may be launched through a transient shell. Prefer the actual
// Codex ancestor when present, so the route survives that shell exiting.
func codexOwner(ctx context.Context, pid int) int {
	seen := map[int]bool{}
	for n := 0; n < 24 && pid > 1; n++ {
		if seen[pid] {
			return 0
		}
		seen[pid] = true
		if strings.TrimSuffix(strings.ToLower(filepath.Base(processName(ctx, pid))), ".exe") == "codex" {
			return pid
		}
		pid = processParent(ctx, pid)
	}
	return 0
}
