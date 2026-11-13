package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"net.potafree/shinphony/hook/internal/notifier"
)

// Session-level agent events. Like moshi-hook, every turn boundary is
// reported and the daemon decides how loudly: a banner, or a silent push that
// only updates the inbox. Bounded excerpts (reply as title, prompt as body,
// as Moshi does) travel with the event; nothing else from the session does.
type agentEvent struct {
	Source  *hookSource `json:"source,omitempty"`
	Agent   string      `json:"agent"`
	Kind    string      `json:"kind"`
	Session string      `json:"session"`
	Mux     string      `json:"mux,omitempty"`
	Armed   bool        `json:"armed,omitempty"`
	Title   string      `json:"title,omitempty"`
	Body    string      `json:"body,omitempty"`
	Project string      `json:"project,omitempty"`
}

var agentEventKinds = map[string]bool{"session_start": true, "prompt": true, "stop": true, "approval": true, "question": true, "session_end": true}

func (e agentEvent) valid() bool {
	if e.Source != nil && (e.Agent != "codex" || e.Source.Agent != e.Agent || !identifier.MatchString(e.Source.Thread) || e.Session != sessionKey(e.Agent, e.Source.Thread) || e.Source.ParentPID <= 1) {
		return false
	}
	return (e.Agent == "claude" || e.Agent == "dsh" || e.Agent == "codex") && agentEventKinds[e.Kind] &&
		identifier.MatchString(e.Session) && (e.Mux == "" || e.Mux == "hc" || e.Mux == "tmux" || e.Mux == "zellij" || e.Mux == "herdr" || e.Mux == "screen") &&
		excerpt(e.Title, 80, false) == e.Title && excerpt(e.Body, 200, true) == e.Body && excerpt(e.Project, 64, false) == e.Project
}

// excerpt keeps the first chars characters (not bytes) of s without control
// or bidi characters; single-line unless multiline (then at most six lines).
func excerpt(s string, chars int, multiline bool) string {
	s = cleanText(s, len(s))
	if !multiline {
		s = strings.Join(strings.Fields(s), " ")
	} else {
		s = strings.ReplaceAll(s, "\t", " ")
		if lines := strings.Split(s, "\n"); len(lines) > 6 {
			s = strings.Join(lines[:6], "\n")
		}
	}
	if r := []rune(s); len(r) > chars {
		s = string(r[:chars])
	}
	return strings.TrimSpace(s)
}

// armRE matches an explicit request to be notified when this turn ends:
// a standalone `!n` or `#notify`, or a short phrase.
var armRE = regexp.MustCompile(`(?i)(^|\s)(!n|#notify)(\s|$)|完成后通知我|做完通知我|好了通知我|notify me when (done|finished)`)

func wantsNotify(prompt string) bool { return armRE.MatchString(prompt) }

// harnessRE matches blocks Claude Code injects into the prompt of a
// UserPromptSubmit event (background task results, reminders). They are not
// what the user typed and must not become the task summary.
// Codex adds send_user_message_question_reply: the answer to its own
// request_user_input question, recorded as a user message.
var harnessRE = regexp.MustCompile(`(?s)<(task-notification|system-reminder|local-command-caveat|local-command-stdout|local-command-stderr|send_user_message_question_reply)>.*?</(task-notification|system-reminder|local-command-caveat|local-command-stdout|local-command-stderr|send_user_message_question_reply)>`)

var questionReplyRE = regexp.MustCompile(`(?s)<send_user_message_question_reply>(.*?)</send_user_message_question_reply>`)

// questionReplies reads Codex's answer blocks: a JSON array of
// {question, answer, questionItemId}. Malformed blocks yield nothing.
func questionReplies(prompt string) (out []struct{ Question, Answer string }) {
	for _, m := range questionReplyRE.FindAllStringSubmatch(prompt, -1) {
		var items []struct {
			Question string `json:"question"`
			Answer   string `json:"answer"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(m[1])), &items) != nil {
			continue
		}
		for _, it := range items {
			if q, a := strings.TrimSpace(it.Question), strings.TrimSpace(it.Answer); q != "" || a != "" {
				out = append(out, struct{ Question, Answer string }{q, a})
			}
		}
	}
	return out
}

// injectedOnly reports a prompt that is one unknown tag-wrapped block
// (`<some_tag>…</some_tag>`): something an agent injected, never shown raw.
func injectedOnly(prompt string) bool {
	p := strings.TrimSpace(prompt)
	m := injectedTagRE.FindStringSubmatch(p)
	return m != nil && strings.HasSuffix(p, "</"+m[1]+">")
}

var injectedTagRE = regexp.MustCompile(`^<([a-z][a-z0-9_:-]{2,63})>`)

var (
	taskNoteRE   = regexp.MustCompile(`(?s)<task-notification>(.*?)</task-notification>`)
	taskFieldRE  = regexp.MustCompile(`(?s)<(status|summary)>(.*?)</(?:status|summary)>`)
	quotedNameRE = regexp.MustCompile(`"([^"]{1,120})"`)
)

// harnessSummary turns Claude Code's background-task notifications into a
// short readable line, e.g. `Background command "Build the app" completed
// (exit code 0)` → "Background task done: Build the app". Several finished
// tasks are counted. Anything unrecognised gets a neutral line.
func harnessSummary(prompt string) string {
	notes := taskNoteRE.FindAllStringSubmatch(prompt, -1)
	if len(notes) == 0 {
		return "Continuing on its own"
	}
	var lines []string
	failed := 0
	for _, n := range notes {
		fields := map[string]string{}
		for _, f := range taskFieldRE.FindAllStringSubmatch(n[1], -1) {
			fields[f[1]] = strings.TrimSpace(f[2])
		}
		status := strings.ToLower(fields["status"])
		summary := fields["summary"]
		name := summary
		if m := quotedNameRE.FindStringSubmatch(summary); m != nil {
			name = m[1]
		}
		bad := status == "failed" || status == "killed" || strings.Contains(summary, "failed") ||
			(strings.Contains(summary, "exit code") && !strings.Contains(summary, "exit code 0)"))
		verb := "done"
		if bad {
			verb = "failed"
			failed++
		} else if status != "" && status != "completed" {
			verb = status
		}
		if name == "" {
			lines = append(lines, "Background task "+verb)
		} else {
			lines = append(lines, "Background task "+verb+": "+name)
		}
	}
	if len(lines) == 1 {
		return lines[0]
	}
	head := fmt.Sprintf("%d background tasks finished", len(lines))
	if failed > 0 {
		head += fmt.Sprintf(" (%d failed)", failed)
	}
	return head + "\n" + strings.Join(lines, "\n")
}

// questionOptions lists the suggested answers ("1. Yes\n2. No"); several
// questions list their texts instead.
func questionOptions(qs []notifier.Question) string {
	var lines []string
	if len(qs) > 1 {
		for i, q := range qs {
			lines = append(lines, fmt.Sprintf("%d. %s", i+1, q.Text))
		}
		return strings.Join(lines, "\n")
	}
	for i, o := range qs[0].Options {
		lines = append(lines, fmt.Sprintf("%d. %s", i+1, o))
	}
	return strings.Join(lines, "\n")
}

// userPromptText is the part of a prompt the user actually typed.
func userPromptText(prompt string) string {
	return strings.TrimSpace(harnessRE.ReplaceAllString(prompt, ""))
}

// multiplexer reports the terminal multiplexer the agent runs in, if any;
// outside one there is no pane a notification could open.
func multiplexer(getenv func(string) string) string {
	switch {
	case getenv("HC_TERMINAL_ID") != "" && getenv("HC_TERMINAL_SOCKET") != "":
		return "hc"
	case getenv("TMUX_PANE") != "" && getenv("TMUX") != "":
		return "tmux"
	case getenv("ZELLIJ") != "":
		return "zellij"
	case getenv("HERDR_ENV") != "":
		return "herdr"
	case getenv("STY") != "":
		return "screen"
	}
	return ""
}

func sessionKey(agent, session string) string {
	sum := sha256.Sum256([]byte("shinphony-session-v1\x00" + agent + "\x00" + session))
	return hex.EncodeToString(sum[:16])
}

func agentEventFromHook(agent string, h notifier.HookInfo, getenv func(string) string) (agentEvent, bool) {
	e := agentEvent{Agent: agent, Session: sessionKey(agent, h.Session), Mux: multiplexer(getenv), Project: excerpt(filepath.Base(h.Cwd), 64, false)}
	if e.Project == "." || e.Project == string(filepath.Separator) {
		e.Project = ""
	}
	switch h.Event {
	case "SessionStart":
		e.Kind = "session_start"
	case "UserPromptSubmit":
		prompt := userPromptText(h.Prompt)
		e.Kind, e.Armed, e.Body = "prompt", wantsNotify(prompt), excerpt(prompt, 200, true)
		if replies := questionReplies(h.Prompt); prompt == "" && len(replies) > 0 {
			// The user answered the agent's question: say which, and the answer.
			e.Title = excerpt("Answered: "+replies[0].Question, 80, false)
			e.Body = excerpt(replies[0].Answer, 200, true)
			if len(replies) > 1 {
				e.Title = fmt.Sprintf("Answered %d questions", len(replies))
				var lines []string
				for _, r := range replies {
					lines = append(lines, r.Question+" → "+r.Answer)
				}
				e.Body = excerpt(strings.Join(lines, "\n"), 200, true)
			}
		} else if prompt == "" && strings.TrimSpace(h.Prompt) != "" {
			// Only harness-injected text: describe it, never show the raw XML.
			e.Body = excerpt(harnessSummary(h.Prompt), 200, true)
		} else if injectedOnly(prompt) {
			// An injected block we do not know yet: neutral, never raw markup.
			e.Body = "Continuing on its own"
		}
	case "Stop":
		if h.Active {
			return e, false
		}
		e.Kind, e.Title = "stop", excerpt(h.Reply, 80, false)
	case "PreToolUse":
		// Installed only for the question tools; anything else is ignored.
		if len(h.Questions) == 0 {
			return e, false
		}
		e.Kind, e.Title, e.Body = "question", excerpt(h.Questions[0].Text, 80, false), excerpt(questionOptions(h.Questions), 200, true)
		if len(h.Questions) > 1 {
			e.Title = fmt.Sprintf("%d questions", len(h.Questions))
		}
	case "PermissionRequest":
		// Moshi shows the command behind an approval so it can be judged from
		// the lock screen.
		tool := h.Tool
		if tool == "" {
			tool = "a tool"
		}
		e.Kind, e.Title, e.Body = "approval", excerpt("Allow "+tool+"?", 80, false), excerpt(h.Command, 200, true)
	case "Notification":
		switch h.Kind {
		case "permission_prompt":
			e.Kind = "approval"
		case "elicitation_dialog":
			e.Kind = "question"
		default:
			return e, false
		}
		e.Title = excerpt(h.Message, 80, false)
	case "SessionEnd":
		e.Kind = "session_end"
	default:
		return e, false
	}
	return e, true
}

func postAgentEvent(ctx context.Context, dir string, e agentEvent) error {
	body, _ := json.Marshal(e)
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/v1/agent-events", bytes.NewReader(body))
	resp, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 {
		return errors.New("agent_event_rejected")
	}
	return nil
}

type sessionState struct {
	start  time.Time
	armed  bool
	prompt string
	seen   time.Time
	// The question the agent asked and the user has not answered yet.
	question, options string
}

// tracker holds per-session turn state (in memory: a restart only forgets
// in-flight turns) and the push rate limit shared by all agent events.
type tracker struct {
	mu       sync.Mutex
	sessions map[string]*sessionState
	tokens   float64
	refilled time.Time
}

const maxTrackedSessions = 1024

func newTracker() *tracker { return &tracker{sessions: map[string]*sessionState{}} }

// eventDetails is the relay's v2 agent-event projection (server/agent-event.mjs).
type eventDetails struct {
	Category   string `json:"category"`
	Agent      string `json:"agent"`
	Session    string `json:"session"`
	Title      string `json:"title,omitempty"`
	Body       string `json:"body,omitempty"`
	Project    string `json:"project,omitempty"`
	Visibility string `json:"visibility"`
}

type decision struct {
	Status, ID, Reason string
	Details            *eventDetails
}

// decide maps a hook event to the event to send, or a reason not to.
func (t *tracker) decide(e agentEvent, s settings, now time.Time) decision {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := e.Agent + ":" + e.Session
	st := t.sessions[key]
	if st == nil {
		t.evict()
		st = &sessionState{}
		t.sessions[key] = st
	}
	st.seen = now
	d := &eventDetails{Agent: e.Agent, Session: e.Session, Project: e.Project, Visibility: "silent"}
	status, id := "completed", ""
	switch e.Kind {
	case "prompt":
		// Any new prompt, including the agent's recorded answer, closes the question.
		st.question, st.options = "", ""
		st.start, st.armed, st.prompt = now, e.Armed, e.Body
		d.Category, d.Title, d.Body = "task_started", e.Title, e.Body
		id = eventID(key, "prompt", strconv.FormatInt(now.UnixNano(), 10))
	case "session_start":
		d.Category, id = "session_started", eventID(key, "start", strconv.FormatInt(now.UnixNano(), 10))
	case "session_end":
		delete(t.sessions, key)
		d.Category, id = "session_ended", eventID(key, "end", strconv.FormatInt(now.UnixNano(), 10))
	case "approval", "question":
		// Someone has to answer: always a banner. Show the command when the
		// hook has one (Codex), else what the user asked for.
		status, d.Visibility, d.Title, d.Body = "attention", "banner", e.Title, e.Body
		if e.Kind == "question" && e.Title != "" {
			st.question, st.options = e.Title, e.Body
		} else if e.Kind == "question" && st.question != "" {
			// Claude's elicitation notification after AskUserQuestion carries no
			// text: keep the question we already have, without a second banner.
			d.Title, d.Body, d.Visibility = st.question, st.options, "silent"
		}
		if d.Body == "" {
			d.Body = st.prompt
		}
		d.Category = map[string]string{"approval": "approval_required", "question": "question"}[e.Kind]
		id = eventID(key, e.Kind, strconv.FormatInt(now.UnixNano(), 10))
	case "stop":
		start, armed, prompt := st.start, st.armed, st.prompt
		st.start, st.armed = time.Time{}, false
		long := !start.IsZero() && now.Sub(start) >= time.Duration(s.LongTurnSeconds)*time.Second
		banner := armed || s.TurnCompletePush == "all" || (s.TurnCompletePush == "long" && long)
		if e.Mux == "" && s.SuppressWithoutMux && !armed {
			banner = false
		}
		if banner {
			d.Visibility = "banner"
		}
		if start.IsZero() {
			start = now
		}
		d.Category, d.Title, d.Body = "task_complete", e.Title, prompt
		id = eventID(key, "stop", strconv.FormatInt(start.UnixNano(), 10))
		if st.question != "" {
			// Codex's async question ends the turn at once: the turn is not done,
			// it waits for the answer. Stay "needs you" (banner already sent).
			status, d.Category, d.Title, d.Body, d.Visibility = "attention", "question", st.question, st.options, "silent"
		}
	}
	if !t.take(s.RateLimitPerMinute, now) {
		return decision{Reason: "rate_limited"}
	}
	return decision{Status: status, ID: id, Details: d}
}

// allow spends one push from the shared budget (scripts share it with agents).
func (t *tracker) allow(perMinute int, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.take(perMinute, now)
}

// take is a token bucket: up to perMinute pushes, refilled continuously.
func (t *tracker) take(perMinute int, now time.Time) bool {
	limit := float64(perMinute)
	if t.refilled.IsZero() {
		t.tokens = limit
	} else {
		t.tokens += now.Sub(t.refilled).Minutes() * limit
	}
	if t.tokens > limit {
		t.tokens = limit
	}
	t.refilled = now
	if t.tokens < 1 {
		return false
	}
	t.tokens--
	return true
}

func (t *tracker) evict() {
	if len(t.sessions) < maxTrackedSessions {
		return
	}
	var oldest string
	for k, s := range t.sessions {
		if oldest == "" || s.seen.Before(t.sessions[oldest].seen) {
			oldest = k
		}
	}
	delete(t.sessions, oldest)
}

func eventID(parts ...string) string {
	sum := sha256.Sum256([]byte("agent-event-v1\x00" + strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}
