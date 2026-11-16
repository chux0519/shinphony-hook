package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"net.potafree/shinphony/hook/internal/notifier"
)

func TestAgyHookKind(t *testing.T) {
	if _, ok := hookKind(nil); ok {
		t.Fatal("empty arguments are not a hook")
	}
	if _, ok := hookKind([]string{"status"}); ok {
		t.Fatal("commands are not hooks")
	}
	for _, kind := range []string{"codex-notify-all", "codex-notify-chain", "claude-hook-all", "dsh-hook-all", "codex-hook-all", "agy-hook"} {
		if got, ok := hookKind([]string{kind, "Stop"}); !ok || got != kind {
			t.Fatal(kind, got, ok)
		}
	}
}

// The event name is passed by the installed command; payload fields are used
// only where the official contract names them.
func TestAgyEventMapping(t *testing.T) {
	hc := env(map[string]string{"HC_TERMINAL_ID": "t1", "HC_TERMINAL_SOCKET": "/tmp/s"})
	session := sessionKey("agy", "c")
	for _, tc := range []struct {
		event, raw, kind, title, body string
		armed                         bool
	}{
		{"SessionStart", `{"conversationId":"c","workspacePaths":["/src/hook"],"lastUserInput":"fix"}`, "session_start", "", "", false},
		{"PreInvocation", `{"conversationId":"c","workspacePaths":["/src/hook"],"invocationNum":2,"lastUserInput":"fix the tests"}`, "invocation", "", "fix the tests", false},
		{"PreInvocation", `{"conversationId":"c","invocationNum":0,"lastUserInput":"跑完测试，完成后通知我"}`, "invocation", "", "跑完测试，完成后通知我", true},
		{"PreToolUse", `{"conversationId":"c","toolCall":{"name":"ask_question","args":{"questions":[{"question":"Which file?","options":["a.go","b.go"]}]}}}`, "question", "Which file?", "1. a.go\n2. b.go", false},
		{"PreToolUse", `{"conversationId":"c","toolCall":{"name":"ask_question","args":{"questions":[{"question":"A?"},{"question":"B?"}]}}}`, "question", "2 questions", "1. A?\n2. B?", false},
		{"PreToolUse", `{"conversationId":"c","toolCall":{"name":"ask_question","args":{}}}`, "question", "Antigravity needs an answer", "", false},
		{"PreToolUse", `{"conversationId":"c","toolCall":{"name":"ask_permission","args":{"Action":"grant","Target":"read_file(/etc)","Reason":"needs config"}}}`, "approval", "Allow grant read_file(/etc)?", "needs config", false},
		{"PreToolUse", `{"conversationId":"c","toolCall":{"name":"ask_permission","args":{}}}`, "approval", "Allow permission?", "", false},
		// An ordinary tool call proves nothing about waiting for the user.
		{"PreToolUse", `{"conversationId":"c","toolCall":{"name":"run_command","args":{"CommandLine":"npm test"}}}`, "", "", "", false},
		{"PostToolUse", `{"conversationId":"c","toolCall":{"name":"ask_question","args":{}}}`, "resume", "", "", false},
		{"PostToolUse", `{"conversationId":"c","toolCall":{"name":"write_to_file","args":{}}}`, "", "", "", false},
		{"Stop", `{"conversationId":"c","executionNum":1,"terminationReason":"model_stop","fullyIdle":true}`, "stop", "", "", false},
		{"Stop", `{"conversationId":"c","executionNum":1,"terminationReason":"model_stop","fullyIdle":false}`, "background", "", "", false},
		{"Stop", `{"conversationId":"c","terminationReason":"model_stop"}`, "background", "", "", false},
		{"Stop", `{"conversationId":"c","terminationReason":"error","error":"/secret/path boom","fullyIdle":true}`, "failure", "Antigravity stopped with an error", "", false},
		{"Stop", `{"conversationId":"c","terminationReason":"max_steps_exceeded","fullyIdle":true}`, "failure", "Antigravity reached the step limit", "", false},
		{"Stop", `{"conversationId":"c","terminationReason":"user_cancelled","fullyIdle":true}`, "", "", "", false},
	} {
		h, ok := notifier.ParseAgyHook(tc.event, []byte(tc.raw))
		if !ok {
			t.Fatal(tc.raw)
		}
		e, ok := agentEventFromAgy(h, hc)
		if ok != (tc.kind != "") {
			t.Fatalf("%s: %+v %v", tc.raw, e, ok)
		}
		if !ok {
			continue
		}
		if e.Agent != "agy" || e.Session != session || e.Mux != "hc" || e.Kind != tc.kind ||
			e.Title != tc.title || e.Body != tc.body || e.Armed != tc.armed || !e.valid() {
			t.Fatalf("%s: %+v", tc.raw, e)
		}
	}
	// Without a terminal the event is still valid; the App falls back to the host.
	e, ok := agentEventFromAgy(notifier.AgyHook{Event: "PreInvocation", Session: "c"}, env(nil))
	if !ok || e.Mux != "" || !e.valid() || e.Project != "" {
		t.Fatal(e, ok)
	}
	// Round 02: agy sends its terminal's route facts like every other agent, and
	// a source that names another session is still refused.
	e.Source = &hookSource{Agent: "agy", Thread: "c", ParentPID: 2, HcAddress: "t3", HcSession: "default"}
	e.cleanRoute()
	if !e.valid() {
		t.Fatalf("a source identifying this session must be accepted: %+v", e)
	}
	other := *e.Source
	other.Thread = "d"
	e.Source = &other
	if e.valid() {
		t.Fatalf("accepted a source for another session: %+v", e.Source)
	}
}

func agySettings() settings {
	return settings{TurnCompletePush: "all", LongTurnSeconds: 60, RateLimitPerMinute: 60}
}

// One execution: start, several model calls and questions, one completion; the
// start time and the explicit notification request are never reset.
func TestAgyTurnTimeline(t *testing.T) {
	tr := newTracker()
	s := agySettings()
	now := time.Unix(1_800_000_000, 0)
	session := sessionKey("agy", "c")
	ev := func(kind, title, body string) agentEvent {
		return agentEvent{Agent: "agy", Session: session, Kind: kind, Title: title, Body: body}
	}
	start := func(invocation, steps int, body string) agentEvent {
		e := ev("invocation", "", body)
		e.Invocation, e.Steps = agyPtr(invocation), agyPtr(steps)
		e.Armed = wantsNotify(body)
		return e
	}
	stop := func(execution int) agentEvent {
		e := ev("stop", "", "")
		e.Execution = agyPtr(execution)
		return e
	}
	if d := tr.decide(ev("session_start", "", ""), s, now); d.Status != "completed" || d.Details.Category != "session_started" {
		t.Fatal(d)
	}
	first := tr.decide(start(0, 0, "fix the tests !n"), s, now)
	if first.Status != "completed" || first.Details.Category != "task_started" || first.Details.Visibility != "silent" || first.ID == "" {
		t.Fatal(first)
	}
	// Later model calls in the same execution are not new turns. A replayed
	// counters pair is stale; a genuinely advanced one keeps the same clock.
	if d := tr.decide(start(0, 0, "fix the tests !n"), s, now.Add(10*time.Second)); d.Status != "" || d.Reason != "stale_invocation" {
		t.Fatal(d)
	}
	if d := tr.decide(start(1, 4, "fix the tests !n"), s, now.Add(11*time.Second)); d.Status != "" || d.Reason != "already_running" {
		t.Fatal(d)
	}
	q := tr.decide(ev("question", "Which file?", "1. a.go\n2. b.go"), s, now.Add(20*time.Second))
	if q.Status != "attention" || q.Details.Category != "question" || q.Details.Visibility != "banner" {
		t.Fatal(q)
	}
	if d := tr.decide(ev("question", "Which file?", "1. a.go\n2. b.go"), s, now.Add(21*time.Second)); d.Status != "" || d.Reason != "duplicate_question" {
		t.Fatal(d)
	}
	// The answer resumes the same turn without restarting its clock.
	r := tr.decide(ev("resume", "", ""), s, now.Add(30*time.Second))
	if r.Status != "completed" || r.Details.Category != "task_started" || r.Details.Visibility != "silent" {
		t.Fatal(r)
	}
	done := tr.decide(stop(1), s, now.Add(90*time.Second))
	if done.Status != "completed" || done.Details.Category != "task_complete" || done.Details.Visibility != "banner" ||
		done.Details.Body != "fix the tests !n" || done.ID == "" {
		t.Fatal(done)
	}
	// A duplicate Stop is not a second completion.
	if d := tr.decide(stop(1), s, now.Add(91*time.Second)); d.Status != "" || d.Reason != "stale_execution" {
		t.Fatal(d)
	}
	// The same prompt twice in a row is two turns, not one merged task.
	// initialNumSteps is the trajectory length, so a later turn cannot go back.
	second := tr.decide(start(2, 8, "fix the tests !n"), s, now.Add(100*time.Second))
	if second.Status != "completed" || second.ID == first.ID || second.Details.Category != "task_started" {
		t.Fatal(second, first)
	}
	again := tr.decide(stop(2), s, now.Add(130*time.Second))
	if again.Status != "completed" || again.ID == "" || again.ID == done.ID {
		t.Fatal(again)
	}
}

// Stop only completes the task when fullyIdle is true and the reason is the
// normal one; errors and unknown reasons never claim success.
func TestAgyStopNegatives(t *testing.T) {
	tr := newTracker()
	s := agySettings()
	now := time.Unix(1_800_000_000, 0)
	session := sessionKey("agy", "c")
	ev := func(kind, title string) agentEvent {
		return agentEvent{Agent: "agy", Session: session, Kind: kind, Title: title, Body: "run the build"}
	}
	tr.decide(ev("invocation", ""), s, now)
	// Background work still running: no completion, no new state, no push.
	if d := tr.decide(ev("background", ""), s, now.Add(5*time.Second)); d.Status != "" || d.Reason != "background_running" {
		t.Fatal(d)
	}
	if d := tr.decide(ev("background", ""), s, now.Add(6*time.Second)); d.Status != "" || d.Reason != "background_running" {
		t.Fatal(d)
	}
	// An unrecognised termination reason proves nothing.
	// (The CLI drops it before sending, so the daemon sees no event at all.)
	// The eventual real stop completes once, measured from the first call.
	done := tr.decide(ev("stop", ""), s, now.Add(120*time.Second))
	if done.Status != "completed" || done.Details.Body != "run the build" || done.Details.Visibility != "banner" {
		t.Fatal(done)
	}
	if d := tr.decide(ev("stop", ""), s, now.Add(121*time.Second)); d.Status != "" {
		t.Fatal(d)
	}
	// An error stops the turn as failed, once, and clears the question.
	tr = newTracker()
	tr.decide(ev("invocation", ""), s, now)
	tr.decide(ev("question", "Continue?"), s, now.Add(time.Second))
	failed := tr.decide(ev("failure", "Antigravity stopped with an error"), s, now.Add(10*time.Second))
	if failed.Status != "failed" || failed.Details.Category != "error" || failed.Details.Visibility != "banner" ||
		failed.Details.Title != "Antigravity stopped with an error" || failed.Details.Body != "run the build" {
		t.Fatal(failed)
	}
	if d := tr.decide(ev("failure", "Antigravity stopped with an error"), s, now.Add(11*time.Second)); d.Status != "" || d.Reason != "already_stopped" {
		t.Fatal(d)
	}
	// A Stop that arrives before any model call still reports completion, as
	// for every other agent, but only once.
	tr = newTracker()
	if d := tr.decide(ev("stop", ""), s, now); d.Status != "completed" || d.ID == "" {
		t.Fatal(d)
	}
}

func TestAgyQuestionNeedsAnswerUntilResumed(t *testing.T) {
	tr := newTracker()
	s := agySettings()
	now := time.Unix(1_800_000_000, 0)
	session := sessionKey("agy", "c")
	ev := func(kind, title, body string) agentEvent {
		return agentEvent{Agent: "agy", Session: session, Kind: kind, Title: title, Body: body}
	}
	tr.decide(ev("invocation", "", "deploy it"), s, now)
	tr.decide(ev("question", "Deploy where?", "1. prod\n2. staging"), s, now.Add(time.Second))
	// A different question replaces the open one with its own banner.
	next := tr.decide(ev("question", "Confirm?", ""), s, now.Add(2*time.Second))
	if next.Status != "attention" || next.Details.Title != "Confirm?" {
		t.Fatal(next)
	}
	// After the answer the turn runs again; the stop is a completion, not
	// another "needs you".
	tr.decide(ev("resume", "", ""), s, now.Add(3*time.Second))
	done := tr.decide(ev("stop", "", ""), s, now.Add(4*time.Second))
	if done.Status != "completed" || done.Details.Category != "task_complete" || done.Details.Visibility != "banner" {
		t.Fatal(done)
	}
	// Late events for a finished execution are dropped.
	if d := tr.decide(ev("resume", "", ""), s, now.Add(5*time.Second)); d.Status != "" || d.Reason != "stale_event" {
		t.Fatal(d)
	}
	if d := tr.decide(ev("background", "", ""), s, now.Add(6*time.Second)); d.Status != "" || d.Reason != "already_stopped" {
		t.Fatal(d)
	}
	// A late SessionStart cannot reopen the turn; only a newer invocation can.
	tr.decide(ev("session_start", "", ""), s, now.Add(7*time.Second))
	resumed := ev("invocation", "", "next turn")
	resumed.Invocation, resumed.Steps = agyPtr(3), agyPtr(0)
	if d := tr.decide(resumed, s, now.Add(8*time.Second)); d.Status != "completed" || d.Details.Category != "task_started" {
		t.Fatal(d)
	}
}

// Through the real installed hook entry: the payload reaches the private
// daemon endpoint and stdout stays neutral for the agent.
func TestAgyHookSubprocess(t *testing.T) {
	if os.Getenv("SHINPHONY_AGY_TEST_CHILD") != "1" {
		return
	}
	hookCLI("agy-hook", []string{os.Getenv("SHINPHONY_AGY_TEST_EVENT")})
	os.Exit(0)
}

func TestAgyHookCLIReachesDaemon(t *testing.T) {
	dir := privateTemp(t)
	canonical, err := serviceExecutable(dir)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan agentEvent, 6)
	// The child gets one known terminal, never whatever this test process
	// happens to run inside.
	testEnv := func(extra ...string) []string {
		var out []string
		for _, v := range os.Environ() {
			drop := false
			for _, key := range []string{"HC_TERMINAL_ID=", "HC_TERMINAL_SOCKET=", "HC_SESSION=", "TMUX=", "TMUX_PANE=", "SHINPHONY_AGY_TEST_"} {
				drop = drop || strings.HasPrefix(v, key)
			}
			if !drop {
				out = append(out, v)
			}
		}
		return append(out, extra...)
	}
	run := func(event, payload string) (string, *agentEvent, time.Duration) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, canonical, "-test.run=^TestAgyHookSubprocess$")
		cmd.Env = testEnv("SHINPHONY_AGY_TEST_CHILD=1", "SHINPHONY_AGY_TEST_EVENT="+event,
			"HC_TERMINAL_ID=t9", "HC_TERMINAL_SOCKET=/tmp/hc/default.sock", "HC_SESSION=default")
		cmd.Stdin = strings.NewReader(payload)
		start := time.Now()
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %s (%v)", event, output, err)
		}
		var got *agentEvent
		select {
		case e := <-received:
			got = &e
		default:
		}
		return strings.TrimSpace(string(output)), got, time.Since(start)
	}
	ln, err := listenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event agentEvent
		if r.URL.Path != "/v1/agent-events" || json.NewDecoder(r.Body).Decode(&event) != nil || !event.valid() {
			http.Error(w, "invalid_event", 400)
			return
		}
		received <- event
		w.Write([]byte(`{"queued":true,"contextStatus":"unavailable"}`))
	})}
	go server.Serve(ln)
	defer server.Close()

	out, event, _ := run("PreInvocation", `{"conversationId":"c-1","workspacePaths":["/src/hook"],"invocationNum":0,"lastUserInput":"fix the tests"}`)
	if out != "{}" {
		t.Fatal("hook printed more than a neutral empty object:", out)
	}
	if event == nil || event.Agent != "agy" || event.Kind != "invocation" || event.Body != "fix the tests" {
		t.Fatal(event)
	}
	// Round 02: the real hook binary sends the route facts of the terminal it ran
	// in, so the inventory can join this event to t9 without guessing.
	if s := event.Source; s == nil || s.Agent != "agy" || s.HcAddress != "t9" || s.HcSession != "default" ||
		s.HcSocket != "/tmp/hc/default.sock" || s.Thread != "c-1" || s.ParentPID <= 1 {
		t.Fatalf("route facts: %+v", s)
	}
	// PreToolUse answers with an empty object: no decision, so permissions and
	// the loop keep their default behavior (never auto_approve / continue).
	out, event, _ = run("PreToolUse", `{"conversationId":"c-1","toolCall":{"name":"ask_permission","args":{"Action":"grant","Target":"network","Reason":"download deps"}}}`)
	// The documented neutral PreToolUse answer delegates to the default policy:
	// it never approves the tool itself.
	if out != `{"decision":"allow"}` || event == nil || event.Kind != "approval" || event.Title != "Allow grant network?" {
		t.Fatal(out, event)
	}
	// A malformed payload is ignored, with the same event-specific neutral
	// output (a Stop still has to permit stopping) and no event.
	out, event, _ = run("Stop", `not json`)
	if out != `{"decision":"allow"}` || event != nil {
		t.Fatal(out, event)
	}
	// An unavailable daemon is bounded and still neutral.
	ln.Close()
	out, _, took := run("Stop", `{"conversationId":"c-1","terminationReason":"model_stop","fullyIdle":true}`)
	if out != `{"decision":"allow"}` || took > 4*time.Second {
		t.Fatal(out, took)
	}
}
