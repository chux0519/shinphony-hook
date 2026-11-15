package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"net.potafree/shinphony/hook/internal/notifier"
)

// agyEvent builds the event the installed hook would send for one payload.
func agyEvent(t *testing.T, event, session string, fields map[string]any) agentEvent {
	t.Helper()
	fields["conversationId"] = session
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	h, ok := notifier.ParseAgyHook(event, raw)
	if !ok {
		t.Fatalf("%s: parse %s", event, raw)
	}
	e, ok := agentEventFromAgy(h, env(nil))
	if !ok {
		t.Fatalf("%s: map %s", event, raw)
	}
	if !e.valid() {
		t.Fatalf("%s: invalid event %+v", event, e)
	}
	return e
}

// Documented counters: invocations carry invocationNum/initialNumSteps, tool
// events carry stepIdx, Stop carries executionNum.
func agyStart(t *testing.T, session string, invocation, steps int, prompt string) agentEvent {
	return agyEvent(t, "PreInvocation", session, map[string]any{
		"invocationNum": invocation, "initialNumSteps": steps, "lastUserInput": prompt})
}

func agyStop(t *testing.T, session string, execution int, idle bool, reason string) agentEvent {
	return agyEvent(t, "Stop", session, map[string]any{
		"executionNum": execution, "terminationReason": reason, "fullyIdle": idle})
}

func agyToolEvent(t *testing.T, event, session string, step int, name string, args map[string]any) agentEvent {
	return agyEvent(t, event, session, map[string]any{
		"stepIdx": step, "toolCall": map[string]any{"name": name, "args": args}})
}

func agyPtr(n int) *int { return &n }

// A replayed Stop for an execution already reported must not complete the next
// turn, even when both turns use the same prompt.
func TestAgyOldStopCannotCompleteNewTurn(t *testing.T) {
	tr, s, now := newTracker(), agySettings(), time.Unix(1_800_000_000, 0)
	start1 := agyStart(t, "c", 0, 0, "same prompt")
	stop1 := agyStop(t, "c", 1, true, "model_stop")
	start2 := agyStart(t, "c", 1, 10, "same prompt")
	tr.decide(start1, s, now)
	if d := tr.decide(stop1, s, now.Add(time.Second)); d.Status != "completed" {
		t.Fatal(d)
	}
	if d := tr.decide(start2, s, now.Add(2*time.Second)); d.Status != "completed" || d.Details.Category != "task_started" {
		t.Fatal("newer invocation must start the next turn", d)
	}
	if d := tr.decide(stop1, s, now.Add(3*time.Second)); d.Status != "" || d.Reason != "stale_execution" {
		t.Fatal("old stop completed the new turn", d)
	}
	// The genuine stop for the second execution still completes it.
	if d := tr.decide(agyStop(t, "c", 2, true, "model_stop"), s, now.Add(4*time.Second)); d.Status != "completed" {
		t.Fatal(d)
	}
}

// A replayed invocation must not reopen a completed turn: only a strictly newer
// documented counter may.
func TestAgyDelayedInvocationCannotReopenCompletedTurn(t *testing.T) {
	tr, s, now := newTracker(), agySettings(), time.Unix(1_800_000_000, 0)
	start := agyStart(t, "c", 0, 0, "same prompt")
	tr.decide(start, s, now)
	tr.decide(agyStop(t, "c", 1, true, "model_stop"), s, now.Add(time.Second))
	if d := tr.decide(start, s, now.Add(2*time.Second)); d.Status != "" || d.Reason != "stale_invocation" {
		t.Fatal("old invocation reopened the turn", d)
	}
	// Same invocation number but more steps is genuinely newer (a resumed
	// conversation after a restart may repeat invocationNum).
	if d := tr.decide(agyStart(t, "c", 0, 1, "same prompt"), s, now.Add(3*time.Second)); d.Status != "completed" {
		t.Fatal("newer steps must reopen", d)
	}
}

func TestAgyDuplicateApprovalIsNotSecondBanner(t *testing.T) {
	tr, s, now := newTracker(), agySettings(), time.Unix(1_800_000_000, 0)
	tr.decide(agyStart(t, "c", 0, 0, "deploy"), s, now)
	event := agyToolEvent(t, "PreToolUse", "c", 3, "ask_permission", map[string]any{"Action": "network", "Target": "example.com"})
	if d := tr.decide(event, s, now.Add(time.Second)); d.Status != "attention" {
		t.Fatal(d)
	}
	if d := tr.decide(event, s, now.Add(2*time.Second)); d.Status != "" || d.Reason != "duplicate_event" {
		t.Fatal("duplicate approval emitted a second banner", d)
	}
	// A different step is a genuinely new request, even with the same target.
	if d := tr.decide(agyToolEvent(t, "PreToolUse", "c", 4, "ask_permission",
		map[string]any{"Action": "network", "Target": "example.com"}), s, now.Add(3*time.Second)); d.Status != "attention" {
		t.Fatal("distinct step was conflated", d)
	}
	// The step is the request identity: another payload for the same step is the
	// same request (even with other options), and an older step is out of order.
	q1 := agyToolEvent(t, "PreToolUse", "c", 5, "ask_question",
		map[string]any{"questions": []any{map[string]any{"question": "Env?", "options": []any{"staging", "local"}}}})
	if d := tr.decide(q1, s, now.Add(4*time.Second)); d.Status != "attention" {
		t.Fatal(d)
	}
	if d := tr.decide(agyToolEvent(t, "PreToolUse", "c", 5, "ask_question",
		map[string]any{"questions": []any{map[string]any{"question": "Env?", "options": []any{"a", "b", "c"}}}}), s, now.Add(5*time.Second)); d.Status != "" || d.Reason != "duplicate_event" {
		t.Fatal("a replay at the same step emitted another banner", d)
	}
	// The same question text at a later step is genuinely new.
	if d := tr.decide(agyToolEvent(t, "PreToolUse", "c", 6, "ask_question",
		map[string]any{"questions": []any{map[string]any{"question": "Env?", "options": []any{"staging", "local"}}}}), s, now.Add(6*time.Second)); d.Status != "attention" {
		t.Fatal("a later step with the same text was conflated", d)
	}
	if d := tr.decide(q1, s, now.Add(7*time.Second)); d.Status != "" || d.Reason != "stale_step" {
		t.Fatal(d)
	}
}

// Crossed or regressed counters cannot admit an old replay: both high-watermarks
// stay monotonic, so a later replay of either counter pair is still stale.
func TestAgyCrossedCountersStayMonotonic(t *testing.T) {
	tr, s, now := newTracker(), agySettings(), time.Unix(1_800_000_000, 0)
	if d := tr.decide(agyStart(t, "c", 5, 20, "turn"), s, now); d.Status != "completed" {
		t.Fatal(d)
	}
	// Higher invocation, lower steps: regressing a provided counter is out of
	// order, so the high-watermark for steps is not lowered.
	if d := tr.decide(agyStart(t, "c", 6, 10, "turn"), s, now.Add(time.Second)); d.Status != "" || d.Reason != "stale_invocation" {
		t.Fatal("regressed steps accepted", d)
	}
	tr.decide(agyStop(t, "c", 1, true, "model_stop"), s, now.Add(2*time.Second))
	// The crossed pair must not have replaced the step high-watermark: replaying
	// the original (5,20) is stale, and so is the crossed (6,10).
	for _, replay := range []agentEvent{agyStart(t, "c", 5, 20, "turn"), agyStart(t, "c", 6, 10, "turn")} {
		if d := tr.decide(replay, s, now.Add(3*time.Second)); d.Status != "" {
			t.Fatal("replay reopened the turn", d)
		}
	}
	if d := tr.decide(agyStart(t, "c", 7, 30, "turn"), s, now.Add(4*time.Second)); d.Status != "completed" {
		t.Fatal("genuinely newer turn refused", d)
	}
}

// A SessionStart that arrives after other events for the same session is late:
// it neither emits a second start nor reopens the finished turn.
func TestAgyLateSessionStartAfterOtherEvents(t *testing.T) {
	tr, s, now := newTracker(), agySettings(), time.Unix(1_800_000_000, 0)
	start := agyEvent(t, "SessionStart", "c", map[string]any{})
	tr.decide(agyStart(t, "c", 0, 0, "fix"), s, now)
	if d := tr.decide(start, s, now.Add(time.Second)); d.Status != "" || d.Reason != "late_session_start" {
		t.Fatal("late SessionStart emitted a start", d)
	}
	tr.decide(agyStop(t, "c", 1, true, "model_stop"), s, now.Add(2*time.Second))
	if d := tr.decide(start, s, now.Add(3*time.Second)); d.Status != "" {
		t.Fatal("late SessionStart reopened the turn", d)
	}
}

func TestAgyNotifyIntentBeyondExcerpt(t *testing.T) {
	// The request sits after the 200-character excerpt.
	e := agyStart(t, "c", 0, 0, strings.Repeat("a", 220)+" 完成后通知我")
	if !e.Armed {
		t.Fatal("explicit notify intent beyond the excerpt was dropped")
	}
	if len([]rune(e.Body)) != 200 {
		t.Fatal("body must stay bounded", len([]rune(e.Body)))
	}
	if !agyStart(t, "c", 1, 0, "!n fix the tests").Armed {
		t.Fatal("short explicit request lost")
	}
	if agyStart(t, "c", 2, 0, strings.Repeat("a", 400)).Armed {
		t.Fatal("plain long prompt armed")
	}
}

func TestAgyIdenticalPromptConsecutiveTurns(t *testing.T) {
	tr, s, now := newTracker(), agySettings(), time.Unix(1_800_000_000, 0)
	first := tr.decide(agyStart(t, "c", 0, 0, "fix the build"), s, now)
	tr.decide(agyStop(t, "c", 1, true, "model_stop"), s, now.Add(time.Second))
	second := tr.decide(agyStart(t, "c", 1, 0, "fix the build"), s, now.Add(2*time.Second))
	if first.Status == "" || second.Status == "" || first.ID == second.ID {
		t.Fatal("identical prompts merged into one task", first, second)
	}
	if d := tr.decide(agyStop(t, "c", 2, true, "model_stop"), s, now.Add(3*time.Second)); d.Status != "completed" || d.ID == "" {
		t.Fatal(d)
	}
}

// Background work keeps the turn open; only the final, fully idle stop
// completes it, once. A late answer cannot revive a finished turn.
func TestAgyBackgroundExecutionAndResume(t *testing.T) {
	tr, s, now := newTracker(), agySettings(), time.Unix(1_800_000_000, 0)
	tr.decide(agyStart(t, "c", 0, 0, "run the tests"), s, now)
	if d := tr.decide(agyStop(t, "c", 1, false, "model_stop"), s, now.Add(time.Second)); d.Status != "" || d.Reason != "background_running" {
		t.Fatal(d)
	}
	// The agent wakes up for the background result without a new user turn.
	if d := tr.decide(agyStart(t, "c", 1, 4, "run the tests"), s, now.Add(2*time.Second)); d.Status != "" || d.Reason != "already_running" {
		t.Fatal("a model call inside the execution restarted the turn", d)
	}
	done := tr.decide(agyStop(t, "c", 2, true, "model_stop"), s, now.Add(3*time.Second))
	if done.Status != "completed" || done.Details.Category != "task_complete" || done.Details.Body != "run the tests" {
		t.Fatal(done)
	}
	if d := tr.decide(agyStop(t, "c", 2, true, "model_stop"), s, now.Add(4*time.Second)); d.Status != "" {
		t.Fatal("duplicate final stop", d)
	}
	// Late tool events for the finished execution change nothing.
	if d := tr.decide(agyToolEvent(t, "PostToolUse", "c", 9, "ask_question", map[string]any{}), s, now.Add(5*time.Second)); d.Status != "" || d.Reason != "stale_event" {
		t.Fatal(d)
	}
}

func TestAgyDuplicateAndLateSessionStart(t *testing.T) {
	tr, s, now := newTracker(), agySettings(), time.Unix(1_800_000_000, 0)
	start := agyEvent(t, "SessionStart", "c", map[string]any{"lastUserInput": "fix"})
	if d := tr.decide(start, s, now); d.Status != "completed" || d.Details.Category != "session_started" {
		t.Fatal(d)
	}
	if d := tr.decide(start, s, now.Add(time.Second)); d.Status != "" || d.Reason != "duplicate_session_start" {
		t.Fatal("duplicate SessionStart emitted another event", d)
	}
	// A late SessionStart after a completed turn must not reopen it.
	tr.decide(agyStart(t, "c", 0, 0, "fix"), s, now.Add(2*time.Second))
	tr.decide(agyStop(t, "c", 1, true, "model_stop"), s, now.Add(3*time.Second))
	if d := tr.decide(start, s, now.Add(4*time.Second)); d.Status != "" {
		t.Fatal("late SessionStart reopened the turn", d)
	}
	// A genuinely newer invocation still starts the next turn.
	if d := tr.decide(agyStart(t, "c", 1, 0, "fix"), s, now.Add(5*time.Second)); d.Status != "completed" {
		t.Fatal(d)
	}
}

func TestAgyDuplicateAndLatePostToolUse(t *testing.T) {
	tr, s, now := newTracker(), agySettings(), time.Unix(1_800_000_000, 0)
	tr.decide(agyStart(t, "c", 0, 0, "deploy"), s, now)
	tr.decide(agyToolEvent(t, "PreToolUse", "c", 3, "ask_question",
		map[string]any{"questions": []any{map[string]any{"question": "Where?", "options": []any{"prod", "staging"}}}}), s, now.Add(time.Second))
	answer := agyToolEvent(t, "PostToolUse", "c", 3, "ask_question", map[string]any{})
	if d := tr.decide(answer, s, now.Add(2*time.Second)); d.Status != "completed" || d.Details.Category != "task_started" {
		t.Fatal(d)
	}
	if d := tr.decide(answer, s, now.Add(3*time.Second)); d.Status != "" || d.Reason != "duplicate_event" {
		t.Fatal("duplicate PostToolUse emitted a second resume", d)
	}
	// An older step is out of order.
	if d := tr.decide(agyToolEvent(t, "PostToolUse", "c", 2, "ask_question", map[string]any{}), s, now.Add(4*time.Second)); d.Status != "" || d.Reason != "stale_step" {
		t.Fatal(d)
	}
}

// Missing, negative or oversized identities are dropped by the parser rather
// than trusted; the tracker then stays conservative instead of reopening work.
func TestAgyIdentityEdgeCases(t *testing.T) {
	base := `"conversationId":"c"`
	for _, tc := range []struct {
		event, raw string
		check      func(notifier.AgyHook) bool
	}{
		{"PreInvocation", `{` + base + `,"invocationNum":-1,"initialNumSteps":-5}`, func(h notifier.AgyHook) bool {
			return h.Invocation == nil && h.Steps == nil
		}},
		{"PreInvocation", `{` + base + `}`, func(h notifier.AgyHook) bool {
			return h.Invocation == nil && h.Steps == nil
		}},
		{"PreToolUse", `{` + base + `,"toolCall":{"name":"ask_permission","args":{}},"stepIdx":-3}`, func(h notifier.AgyHook) bool {
			return h.Step == nil
		}},
		{"Stop", `{` + base + `,"terminationReason":"model_stop","fullyIdle":true,"executionNum":2000000001}`, func(h notifier.AgyHook) bool {
			return h.Execution == nil
		}},
		// A wrong-typed documented field makes the payload malformed: it is
		// dropped instead of trusted with a guessed identity.
		{"PreInvocation", `{` + base + `,"invocationNum":"3"}`, nil},
	} {
		h, ok := notifier.ParseAgyHook(tc.event, []byte(tc.raw))
		if tc.check == nil {
			if ok {
				t.Fatalf("%s %s: malformed identity accepted", tc.event, tc.raw)
			}
			continue
		}
		if !ok || !tc.check(h) {
			t.Fatalf("%s %s: %+v", tc.event, tc.raw, h)
		}
	}
	// Without counters a completed turn is not reopened by another invocation.
	tr, s, now := newTracker(), agySettings(), time.Unix(1_800_000_000, 0)
	tr.decide(agyEvent(t, "PreInvocation", "c", map[string]any{"lastUserInput": "same"}), s, now)
	tr.decide(agyEvent(t, "Stop", "c", map[string]any{"terminationReason": "model_stop", "fullyIdle": true}), s, now.Add(time.Second))
	if d := tr.decide(agyEvent(t, "PreInvocation", "c", map[string]any{"lastUserInput": "same"}), s, now.Add(2*time.Second)); d.Status != "" {
		t.Fatal("absent identity reopened a turn", d)
	}
	// A negative execution number cannot complete anything twice.
	tr2 := newTracker()
	tr2.decide(agyStart(t, "c", 0, 0, "x"), s, now)
	tr2.decide(agyEvent(t, "Stop", "c", map[string]any{"terminationReason": "model_stop", "fullyIdle": true, "executionNum": -1}), s, now.Add(time.Second))
	if d := tr2.decide(agyEvent(t, "Stop", "c", map[string]any{"terminationReason": "model_stop", "fullyIdle": true, "executionNum": -1}), s, now.Add(2*time.Second)); d.Status != "" {
		t.Fatal("negative execution completed twice", d)
	}
}

// Antigravity's extra identities must not reach the other agents' state.
func TestAgyMetadataIsolationFromOldAgents(t *testing.T) {
	tr, s, now := newTracker(), agySettings(), time.Unix(1_800_000_000, 0)
	codex := sessionKey("codex", "thread")
	claude := sessionKey("claude", "session")
	tr.decide(agentEvent{Agent: "codex", Kind: "prompt", Session: codex, Body: "one"}, s, now)
	tr.decide(agentEvent{Agent: "claude", Kind: "prompt", Session: claude, Body: "two"}, s, now)
	// An agy event that reuses those session keys must not touch their turns.
	zero, one := agyPtr(0), agyPtr(1)
	tr.decide(agentEvent{Agent: "agy", Kind: "invocation", Session: codex, Body: "agy", Invocation: zero, Steps: zero}, s, now.Add(time.Second))
	tr.decide(agentEvent{Agent: "agy", Kind: "stop", Session: claude, Execution: one}, s, now.Add(time.Second))
	if d := tr.decide(agentEvent{Agent: "codex", Kind: "stop", Session: codex}, s, now.Add(2*time.Second)); d.Status != "completed" || d.Details.Body != "one" {
		t.Fatal("codex turn disturbed by agy state", d)
	}
	if d := tr.decide(agentEvent{Agent: "claude", Kind: "stop", Session: claude}, s, now.Add(2*time.Second)); d.Status != "completed" || d.Details.Body != "two" {
		t.Fatal("claude turn disturbed by agy state", d)
	}
	// Claude keeps its existing duplicate-Stop behaviour (unchanged).
	if d := tr.decide(agentEvent{Agent: "claude", Kind: "stop", Session: claude}, s, now.Add(3*time.Second)); d.Status != "completed" {
		t.Fatal("claude duplicate stop changed", d)
	}
}

// The neutral contract is per event: `allow` delegates to the default policy
// (PreToolUse) or permits stopping (Stop); everything else injects nothing.
func TestAgyNeutralOutputSchema(t *testing.T) {
	for _, tc := range []struct{ args []string; want string }{
		{[]string{"PreToolUse"}, `{"decision":"allow"}`},
		{[]string{"Stop"}, `{"decision":"allow"}`},
		{[]string{"SessionStart"}, `{}`},
		{[]string{"PreInvocation"}, `{}`},
		{[]string{"PostToolUse"}, `{}`},
		{[]string{"PostInvocation"}, `{}`},
		{[]string{"Unknown"}, `{}`},
		{nil, `{}`},
		{[]string{"Stop", "extra"}, `{}`},
	} {
		_, out := agyNeutralOutput(tc.args)
		if got := strings.TrimSpace(string(out)); got != tc.want {
			t.Fatalf("%v: %s", tc.args, got)
		}
		for _, forbidden := range []string{"auto_approve", "continue", "injectSteps", "permissionOverrides", "overwrite", "force_ask"} {
			if strings.Contains(tc.want, forbidden) || strings.Contains(string(out), forbidden) {
				t.Fatalf("%v: forbidden %s", tc.args, forbidden)
			}
		}
		var parsed map[string]any
		if json.Unmarshal(out, &parsed) != nil {
			t.Fatalf("%v: not JSON", tc.args)
		}
		if decision, ok := parsed["decision"]; ok && decision != "allow" {
			t.Fatalf("%v: unexpected decision %v", tc.args, decision)
		}
	}
}
// H09: a SessionStart keeps one durable identity for its conversation, so a
// daemon restart cannot re-deliver the same start; other agents keep their
// timestamped ID.
func TestAgySessionStartDurableIdentity(t *testing.T) {
	start := agyEvent(t, "SessionStart", "c", map[string]any{"lastUserInput": "fix"})
	first := newTracker().decide(start, agySettings(), time.Unix(1_800_000_000, 0))
	second := newTracker().decide(start, agySettings(), time.Unix(1_800_001_000, 0))
	if first.ID == "" || first.ID != second.ID {
		t.Fatalf("SessionStart identity changed across a tracker restart: %s != %s", first.ID, second.ID)
	}
	if again := newTracker().decide(start, agySettings(), time.Unix(1_800_002_000, 0)); again.ID != first.ID {
		t.Fatal("not deterministic")
	}

	// The durable queue dedupes that ID: a replay after a restart adds nothing.
	dir := privateTemp(t)
	q, err := openQueue(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.db.Close()
	event := Event{Profile: "phone", ID: first.ID, Status: first.Status}
	if _, err := q.enqueueWith(event, `{"category":"session_started","agent":"agy"}`, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := q.enqueueWith(event, `{"category":"session_started","agent":"agy"}`, 2000); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := q.db.QueryRow("SELECT count(*) FROM outbox WHERE event_id=?", first.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("replayed SessionStart produced %d durable events", rows)
	}

	// Existing agents are unchanged: their SessionStart ID still uses the clock.
	session := sessionKey("claude", "s")
	one := newTracker().decide(agentEvent{Agent: "claude", Kind: "session_start", Session: session}, agySettings(), time.Unix(1_800_000_000, 0))
	two := newTracker().decide(agentEvent{Agent: "claude", Kind: "session_start", Session: session}, agySettings(), time.Unix(1_800_000_010, 0))
	if one.ID == "" || one.ID == two.ID {
		t.Fatal("claude SessionStart identity changed")
	}
}
