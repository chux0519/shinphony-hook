package main

// debug-hc-capture is a read-only developer command for acceptance work: it
// captures one existing local hc terminal the way an event would (the agent
// check is skipped on purpose, because there is no agent to be running), and
// prints the snapshot, the network projection and the alert / Live Activity text
// the relay would build from it. It writes nothing: no state directory, no
// queue, no credential, no daemon, no network. The only reads are the existing
// core's hello + terminal.get, exactly like a hook capture.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// The two tables mirror the relay's wording. Keep them in sync with
// server/apns-core.mjs (states, shortStates) and server/live-activity.mjs
// (activityContent). The relay stays authoritative; this is a dry-run preview.
var (
	debugStatusWords  = map[string]string{"completed": "Done", "failed": "Failed", "attention": "Needs you"}
	debugStatusBodies = map[string]string{"completed": "Task completed", "failed": "Task failed", "attention": "Task needs your attention"}
)

type hcDebugReport struct {
	Address      string         `json:"address"`
	Socket       string         `json:"socket"`
	Session      string         `json:"session"`
	Status       string         `json:"status"`
	CapturedInMS int64          `json:"capturedInMs"`
	Snapshot     *localSnapshot `json:"snapshot"`
	Context      *taskContext   `json:"context"`
	APNs         map[string]any `json:"apns"`
	LiveActivity map[string]any `json:"liveActivity"`
	Notes        []string       `json:"notes"`
}

func debugHcCapture(w io.Writer, address, status string) error {
	home, e := os.UserHomeDir()
	if e != nil {
		return errors.New("home_unavailable")
	}
	return debugHcCaptureWith(w, address, status, os.Getenv, home, time.Now().Unix())
}

func debugHcCaptureWith(w io.Writer, address, status string, getenv func(string) string, home string, now int64) error {
	if !hcAddressRE.MatchString(address) {
		return errors.New("invalid_hc_address")
	}
	if _, ok := debugStatusWords[status]; !ok {
		return errors.New("invalid_status")
	}
	socket, session := hcDebugEndpoint(getenv, home)
	if socket == "" {
		return errors.New("no_local_hc_core")
	}
	binary, managed := hcDebugBinaryDigest()
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	started := time.Now()
	c := captureHcSnapshot(ctx, &hookSource{Agent: "codex", Thread: "debug", HcAddress: address, HcSocket: socket, HcSession: session}, "debug", binary, false)
	elapsed := time.Since(started)
	if c == nil {
		return errors.New("hc_capture_unavailable")
	}
	contextJSON, e := json.Marshal(c.taskContext)
	if e != nil {
		return errors.New("context_unavailable")
	}
	report := hcDebugReport{
		Address: address, Socket: socket, Session: session, Status: status,
		CapturedInMS: elapsed.Milliseconds(), Snapshot: c, Context: &c.taskContext,
		APNs: debugAlert(&c.taskContext, status), LiveActivity: debugActivityContent(&c.taskContext, status, now),
		Notes: []string{
			"dry run: nothing was queued, sent or stored",
			"the agent check is skipped here; a real event is only created by an agent under the terminal",
			"the relay remains authoritative for text: this preview mirrors server/apns-core.mjs and server/live-activity.mjs without displayText's Markdown stripping (hook labels are already plain)",
			"context received by the relay: " + string(contextJSON),
		},
	}
	if !managed {
		report.Notes = append(report.Notes, "binary is this build's own sha256, not an installed immutable copy's digest")
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// hcDebugEndpoint finds an existing local core without starting one: an explicit
// HC_SOCKET first, then the state lock herdr writes (its content is the socket
// path), then the runtime-dir and state-dir socket paths. On Windows only
// HC_SOCKET applies; no pipe name is guessed.
func hcDebugEndpoint(getenv func(string) string, home string) (socket, session string) {
	session = getenv("HC_SESSION")
	if session == "" {
		session = "default"
	}
	if !hcSessionNameRE.MatchString(session) || session == "." || session == ".." {
		return "", ""
	}
	if s := getenv("HC_SOCKET"); s != "" {
		if validHcSocket(s) {
			return s, session
		}
		return "", ""
	}
	if runtime.GOOS == "windows" {
		return "", ""
	}
	state := getenv("XDG_STATE_HOME")
	if state == "" {
		state = filepath.Join(home, ".local", "state")
	}
	dir := filepath.Join(state, "herdr-core", session)
	if raw, e := os.ReadFile(filepath.Join(dir, "core.lock")); e == nil {
		if s := strings.TrimSpace(string(raw)); validHcSocket(s) {
			if _, e = os.Stat(s); e == nil {
				return s, session
			}
		}
	}
	for _, candidate := range []string{
		filepath.Join(getenv("XDG_RUNTIME_DIR"), "herdr-core", session+".sock"),
		filepath.Join(dir, session+".sock"),
	} {
		if _, e := os.Stat(candidate); e == nil && validHcSocket(candidate) {
			return candidate, session
		}
	}
	return "", ""
}

var hcSessionNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func hcDebugBinaryDigest() (string, bool) {
	exe, e := os.Executable()
	if e != nil {
		return strings.Repeat("0", 64), false
	}
	if digest, ok := managedBinaryDigest(exe); ok {
		return digest, true
	}
	data, e := os.ReadFile(exe)
	if e != nil {
		return strings.Repeat("0", 64), false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), false
}

// debugAlert mirrors the hc branch of notificationRequest: the parent
// conversation is the title and the helper plus its status the subtitle, or the
// original helper title when there is no parent.
func debugAlert(c *taskContext, status string) map[string]any {
	title, subtitle := c.Session+" · Codex", c.Title
	if c.ParentTitle != "" {
		title = c.ParentTitle
		subtitle = debugStatusWords[status]
		if c.Session != "" {
			subtitle = c.Session + " · " + subtitle
		}
	}
	body := debugStatusBodies[status]
	if c.Preview != "" {
		body += "\n" + c.Preview
	}
	return map[string]any{
		"aps": map[string]any{
			"alert":     map[string]any{"title": title, "subtitle": subtitle, "body": body},
			"sound":     "default",
			"thread-id": "debug:" + c.Thread,
		},
		"shinphony": map[string]any{"version": 1, "eventId": "debug", "hostId": "debug", "status": status, "context": c},
	}
}

// debugActivityContent mirrors activityContent for an event with no
// agent-event details and no multi-session aggregate: the helper keeps its own
// result line, the conversation names the parent, and `helper` is present only
// with a parent.
func debugActivityContent(c *taskContext, status string, now int64) map[string]any {
	conversation := c.ParentTitle
	if conversation == "" {
		conversation = c.Title
	}
	contextJSON, _ := json.Marshal(c)
	out := map[string]any{
		"status": status, "agent": "codex", "title": c.Title, "summary": "",
		"project": c.Session, "updatedAt": now, "eventId": "debug",
		"contextJSON": string(contextJSON),
	}
	if conversation != "" {
		out["conversation"] = conversation
	}
	if c.ParentTitle != "" && c.Session != "" {
		out["helper"] = c.Session
	}
	return out
}
