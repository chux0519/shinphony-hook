package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"net.potafree/shinphony/hook/internal/notifier"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestAgentEventFromHook(t *testing.T) {
	tmux := env(map[string]string{"TMUX": "/tmp/tmux-1/default,1,0", "TMUX_PANE": "%3"})
	for _, tc := range []struct {
		raw, kind, title, body string
		armed                  bool
	}{
		{`{"hook_event_name":"SessionStart","session_id":"s","cwd":"/src/hook"}`, "session_start", "", "", false},
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"fix the tests"}`, "prompt", "", "fix the tests", false},
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"fix the tests !n"}`, "prompt", "", "fix the tests !n", true},
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"跑完测试，完成后通知我"}`, "prompt", "", "跑完测试，完成后通知我", true},
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"<task-notification>\n<task-id>bciyt6zzl</task-id>\n<status>completed</status>\n</task-notification>"}`, "prompt", "", "Background task done", false},
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"<system-reminder>ctx</system-reminder>\nship it !n"}`, "prompt", "", "ship it !n", true},
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"<task-notification>\n<task-id>b1</task-id>\n<status>completed</status>\n<summary>Background command \"Build the sound version\" completed (exit code 0)</summary>\n</task-notification>"}`, "prompt", "", "Background task done: Build the sound version", false},
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"<task-notification><status>failed</status><summary>Background command \"Run tests\" failed with exit code 149</summary></task-notification>"}`, "prompt", "", "Background task failed: Run tests", false},
		// Codex records the user's answer to request_user_input as a user message (2026-11-05 Live Activity).
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"<send_user_message_question_reply>\n[{\"answer\":\"暂无，先完成数据筛查与模型预检\",\"question\":\"有现成的标注数据吗？\",\"questionItemId\":\"[\\\"request_user_input_async\\\",\\\"call_1\\\",0]\"}]\n</send_user_message_question_reply>"}`, "prompt", "Answered: 有现成的标注数据吗？", "暂无，先完成数据筛查与模型预检", false},
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"<send_user_message_question_reply>[{\"answer\":\"A\",\"question\":\"Q1?\"},{\"answer\":\"B\",\"question\":\"Q2?\"}]</send_user_message_question_reply>"}`, "prompt", "Answered 2 questions", "Q1? → A\nQ2? → B", false},
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"<send_user_message_question_reply>not json</send_user_message_question_reply>"}`, "prompt", "", "Continuing on its own", false},
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"<some_future_block>{\"x\":1}</some_future_block>"}`, "prompt", "", "Continuing on its own", false},
		{`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"<b>bold</b> is fine here"}`, "prompt", "", "<b>bold</b> is fine here", false},
		{`{"hook_event_name":"Stop","session_id":"s","last_assistant_message":"All   tests\npass."}`, "stop", "All tests pass.", "", false},
		{`{"hook_event_name":"Stop","session_id":"s","stop_hook_active":true}`, "", "", "", false},
		{`{"hook_event_name":"Notification","session_id":"s","notification_type":"permission_prompt","message":"Claude needs your permission to use Bash"}`, "approval", "Claude needs your permission to use Bash", "", false},
		{`{"hook_event_name":"Notification","session_id":"s","notification_type":"elicitation_dialog"}`, "question", "", "", false},
		{`{"hook_event_name":"Notification","session_id":"s","notification_type":"idle_prompt"}`, "", "", "", false},
		{`{"hook_event_name":"SessionEnd","session_id":"s"}`, "session_end", "", "", false},
		{`{"hook_event_name":"PermissionRequest","session_id":"s","tool_name":"Bash","tool_input":{"command":"npm install ajv"}}`, "approval", "Allow Bash?", "npm install ajv", false},
		{`{"hook_event_name":"PreCompact","session_id":"s"}`, "", "", "", false},
	} {
		h, ok := notifier.ParseHook([]byte(tc.raw))
		if !ok {
			t.Fatal(tc.raw)
		}
		e, ok := agentEventFromHook("claude", h, tmux)
		if ok != (tc.kind != "") || (ok && (e.Kind != tc.kind || e.Armed != tc.armed || e.Mux != "tmux" || e.Title != tc.title || e.Body != tc.body || !e.valid())) {
			t.Fatalf("%s: %+v %v", tc.raw, e, ok)
		}
	}
	h, _ := notifier.ParseHook([]byte(`{"hook_event_name":"SessionStart","session_id":"s","cwd":"/src/hook"}`))
	if e, _ := agentEventFromHook("dsh", h, env(nil)); e.Project != "hook" || e.Mux != "" || e.Session == "s" {
		t.Fatal(e)
	}
	for _, p := range []string{"!nope", "a!n", "notify", "#notifyme"} {
		if wantsNotify(p) {
			t.Fatal(p)
		}
	}
}

func TestExcerpt(t *testing.T) {
	if got := excerpt(strings.Repeat("好", 100), 80, false); got != strings.Repeat("好", 80) {
		t.Fatal(got)
	}
	if got := excerpt("a\nb\tc\u0007\u202e d", 80, false); got != "a b c d" {
		t.Fatalf("%q", got)
	}
	if got := excerpt("1\n2\n3\n4\n5\n6\n7\n8", 200, true); got != "1\n2\n3\n4\n5\n6" {
		t.Fatalf("%q", got)
	}
	// Hooks that send unbounded text are rejected by the daemon.
	if (agentEvent{Agent: "claude", Kind: "stop", Session: "a", Title: strings.Repeat("x", 81)}).valid() {
		t.Fatal("unbounded title accepted")
	}
}

func TestTurnPolicy(t *testing.T) {
	base := settings{TurnCompletePush: "long", LongTurnSeconds: 60, RateLimitPerMinute: 60}
	now := time.Unix(1_800_000_000, 0)
	turn := func(tr *tracker, s settings, e agentEvent, d time.Duration) decision {
		p := e
		p.Kind, p.Body = "prompt", "run the tests"
		tr.decide(p, s, now)
		e.Kind, e.Title = "stop", "Tests pass"
		return tr.decide(e, s, now.Add(d))
	}
	e := agentEvent{Agent: "claude", Session: "a", Mux: "tmux", Project: "hook"}
	// Every turn is reported; the policy only picks banner or silent.
	short := turn(newTracker(), base, e, 10*time.Second)
	if short.Status != "completed" || short.Details.Visibility != "silent" || short.Details.Category != "task_complete" {
		t.Fatal(short)
	}
	long := turn(newTracker(), base, e, 2*time.Minute)
	if d := long.Details; d.Visibility != "banner" || d.Title != "Tests pass" || d.Body != "run the tests" || d.Project != "hook" || d.Agent != "claude" || d.Session != "a" {
		t.Fatal(d)
	}
	tr := newTracker()
	tr.decide(agentEvent{Agent: "claude", Session: "a", Kind: "prompt", Armed: true}, base, now)
	if d := tr.decide(agentEvent{Agent: "claude", Session: "a", Kind: "stop"}, base, now.Add(time.Second)); d.Details.Visibility != "banner" {
		t.Fatal("armed turn not a banner")
	}
	if d := turn(tr, base, e, time.Second); d.Details.Visibility != "silent" {
		t.Fatal("arming leaked into the next turn")
	}
	all := base
	all.TurnCompletePush = "all"
	if d := turn(newTracker(), all, e, time.Second); d.Details.Visibility != "banner" {
		t.Fatal("all")
	}
	off := base
	off.TurnCompletePush = "off"
	if d := turn(newTracker(), off, e, time.Hour); d.Status == "" || d.Details.Visibility != "silent" {
		t.Fatal("off")
	}
	// Outside a multiplexer turns are silent (Moshi's default), approvals are not.
	quiet := all
	quiet.SuppressWithoutMux = true
	plain := e
	plain.Mux = ""
	if d := turn(newTracker(), quiet, plain, time.Hour); d.Details.Visibility != "silent" {
		t.Fatal("outside a multiplexer")
	}
	tr = newTracker()
	tr.decide(agentEvent{Agent: "dsh", Session: "b", Kind: "prompt", Body: "deploy"}, quiet, now)
	if d := tr.decide(agentEvent{Agent: "dsh", Session: "b", Kind: "approval", Title: "Allow Bash?"}, quiet, now); d.Status != "attention" || d.Details.Visibility != "banner" || d.Details.Category != "approval_required" || d.Details.Body != "deploy" {
		t.Fatal(d)
	}
	if d := tr.decide(agentEvent{Agent: "dsh", Session: "b", Kind: "approval", Title: "Allow Bash?", Body: "npm install ajv"}, quiet, now); d.Details.Body != "npm install ajv" {
		t.Fatal("approval must show the command", d.Details)
	}
	if d := tr.decide(agentEvent{Agent: "dsh", Session: "b", Kind: "question"}, quiet, now); d.Details.Category != "question" || d.Status != "attention" {
		t.Fatal(d)
	}
	if d := tr.decide(agentEvent{Agent: "dsh", Session: "b", Kind: "session_start"}, quiet, now); d.Details.Category != "session_started" || d.Details.Visibility != "silent" {
		t.Fatal(d)
	}
	if d := tr.decide(agentEvent{Agent: "dsh", Session: "b", Kind: "session_end"}, quiet, now); d.Details.Category != "session_ended" || len(tr.sessions) != 0 {
		t.Fatal(d, len(tr.sessions))
	}
	// The same turn reported twice is one event; the next turn is another.
	tr = newTracker()
	tr.decide(agentEvent{Agent: "claude", Session: "a", Kind: "prompt"}, all, now)
	id1 := tr.decide(agentEvent{Agent: "claude", Session: "a", Kind: "stop"}, all, now).ID
	tr.decide(agentEvent{Agent: "claude", Session: "a", Kind: "prompt"}, all, now.Add(time.Second))
	id2 := tr.decide(agentEvent{Agent: "claude", Session: "a", Kind: "stop"}, all, now.Add(2*time.Second)).ID
	if id1 == "" || id1 == id2 || !identifier.MatchString(id1) {
		t.Fatal(id1, id2)
	}
}

func TestPushRateLimit(t *testing.T) {
	s := settings{TurnCompletePush: "all", RateLimitPerMinute: 10}
	tr := newTracker()
	now := time.Unix(1_800_000_000, 0)
	sent := 0
	for i := 0; i < 15; i++ {
		if d := tr.decide(agentEvent{Agent: "claude", Session: "a", Kind: "approval"}, s, now); d.Status != "" {
			sent++
		} else if d.Reason != "rate_limited" {
			t.Fatal(d.Reason)
		}
	}
	if sent != 10 {
		t.Fatal(sent)
	}
	if d := tr.decide(agentEvent{Agent: "claude", Session: "a", Kind: "approval"}, s, now.Add(6*time.Second)); d.Status == "" {
		t.Fatal("bucket did not refill")
	}
}

func TestTrackerBounded(t *testing.T) {
	tr := newTracker()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < maxTrackedSessions+50; i++ {
		tr.decide(agentEvent{Agent: "claude", Session: sessionKey("claude", string(rune(i))), Kind: "prompt"}, settings{RateLimitPerMinute: 10}, now.Add(time.Duration(i)))
	}
	if len(tr.sessions) > maxTrackedSessions {
		t.Fatal(len(tr.sessions))
	}
}

func TestSettings(t *testing.T) {
	dir := privateTemp(t)
	if s := loadSettings(dir); s.TurnCompletePush != "off" || s.LongTurnSeconds != 60 || !s.SuppressWithoutMux || s.RateLimitPerMinute != 60 {
		t.Fatal(s)
	}
	for _, bad := range [][2]string{{"turn-complete-push", "sometimes"}, {"long-turn-seconds", "-1"}, {"nope", "on"}, {"rate-limit-per-minute", "0"}} {
		if setSetting(dir, bad[0], bad[1]) == nil {
			t.Fatal(bad)
		}
	}
	if err := setSetting(dir, "turn-complete-push", "long"); err != nil {
		t.Fatal(err)
	}
	if err := setSetting(dir, "suppress-push-without-mux", "off"); err != nil {
		t.Fatal(err)
	}
	if s := loadSettings(dir); s.TurnCompletePush != "long" || s.SuppressWithoutMux {
		t.Fatal(s)
	}
	var out bytes.Buffer
	printSettings(dir, &out)
	if !strings.Contains(out.String(), "turn-complete-push = long\n") || !strings.Contains(out.String(), "long-turn-seconds = 60 (default)") {
		t.Fatal(out.String())
	}
	// A hand-edited invalid value falls back to its default.
	os.WriteFile(settingsPath(dir), []byte(`{"turn-complete-push":"loud"}`), 0600)
	if s := loadSettings(dir); s.TurnCompletePush != "off" {
		t.Fatal(s)
	}
}

func TestTaskSkillUpgrade(t *testing.T) {
	home := privateTemp(t)
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex"))
	dir := filepath.Join(home, "codex", "skills", "shinphony-task-notify")
	os.MkdirAll(dir, 0700)
	path := filepath.Join(dir, "SKILL.md")
	exe := filepath.Join(home, "agent-x")
	// Text of the 2026-10-24 version is only known by hash here, so simulate a
	// user edit and an unmodified current install instead.
	os.WriteFile(path, []byte("my own notes"), 0600)
	if err := installTaskSkill(exe); err == nil || err.Error() != "task_skill_modified_preserved" {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "my own notes" {
		t.Fatal("user edit overwritten")
	}
	os.Remove(path)
	if err := installTaskSkill(exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, taskSkill) {
		t.Fatal("not installed")
	}
	if err := installTaskSkill(exe); err != nil {
		t.Fatal("not idempotent", err)
	}
	// A rename changes routing data, not the skill text or user instructions.
	newExe := filepath.Join(home, managedPrefix+strings.Repeat("a", 64))
	if err := installTaskSkill(newExe); err != nil {
		t.Fatal("rename", err)
	}
	var client struct{ Executable string }
	raw, err := os.ReadFile(filepath.Join(dir, "client.json"))
	if err != nil || json.Unmarshal(raw, &client) != nil || client.Executable != newExe {
		t.Fatal("renamed executable not recorded in skill routing", err)
	}
	// An unmodified earlier version of ours is upgraded in place.
	old := []byte("earlier shinphony skill text")
	sum := sha256.Sum256(old)
	previousTaskSkills[hex.EncodeToString(sum[:])] = true
	defer delete(previousTaskSkills, hex.EncodeToString(sum[:]))
	os.WriteFile(path, old, 0600)
	if err := installTaskSkill(exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, taskSkill) {
		t.Fatal("earlier version not upgraded")
	}
}

// Through the real daemon endpoint and the delivery path: every turn is
// queued, the relay request carries the v2 details, unknown fields are refused.
func TestAgentEventsEndpoint(t *testing.T) {
	home := privateTemp(t)
	t.Setenv("HOME", home)
	dir := filepath.Join(home, "state")
	creds := filepath.Join(home, "credentials")
	os.Mkdir(dir, 0700)
	manager := notifier.Manager{Directory: creds, Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"hostId":"host","hostToken":"` + strings.Repeat("a", 43) + `"}`)), Header: make(http.Header)}, nil
	})}
	if err := manager.Pair("phone", "sandbox", "host", strings.Repeat("b", 43)); err != nil {
		t.Fatal(err)
	}
	delivered := make(chan map[string]any, 10)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, dir, func(c context.Context, e Event) result {
			fields := map[string]any{"eventId": e.ID, "status": e.Status}
			if d, ok := c.Value(agentDetailsKey{}).(json.RawMessage); ok {
				json.Unmarshal(d, &fields)
			}
			delivered <- fields
			return result{Code: "accepted"}
		}, creds)
	}()
	defer func() {
		cancel()
		<-done
	}()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	post := func(e agentEvent) map[string]any {
		t.Helper()
		b, _ := json.Marshal(e)
		var resp *http.Response
		var err error
		for i := 0; i < 200; i++ {
			if resp, err = client.Post("http://local/v1/agent-events", "application/json", bytes.NewReader(b)); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode, out)
		}
		return out
	}
	next := func() map[string]any {
		t.Helper()
		select {
		case f := <-delivered:
			return f
		case <-time.After(5 * time.Second):
			t.Fatal("not delivered")
		}
		return nil
	}
	s := sessionKey("claude", "session-1")
	post(agentEvent{Agent: "claude", Kind: "prompt", Session: s, Body: "run the tests"})
	if f := next(); f["category"] != "task_started" || f["visibility"] != "silent" {
		t.Fatal("prompt must update activity without a banner", f)
	}
	if out := post(agentEvent{Agent: "claude", Kind: "stop", Session: s, Mux: "tmux", Title: "Tests pass", Project: "hook"}); out["queued"] != true || out["visibility"] != "silent" {
		t.Fatal(out)
	}
	if f := next(); f["category"] != "task_complete" || f["title"] != "Tests pass" || f["body"] != "run the tests" || f["visibility"] != "silent" || f["status"] != "completed" || f["session"] != s {
		t.Fatal(f)
	}
	// Explicit opt-in to every turn still honors outside-multiplexer suppression.
	if err := setSetting(dir, "turn-complete-push", "all"); err != nil {
		t.Fatal(err)
	}
	post(agentEvent{Agent: "claude", Kind: "prompt", Session: s})
	next() // silent task_started
	if out := post(agentEvent{Agent: "claude", Kind: "stop", Session: s}); out["visibility"] != "silent" {
		t.Fatal(out)
	}
	if f := next(); f["visibility"] != "silent" {
		t.Fatal(f)
	}
	if err := setSetting(dir, "suppress-push-without-mux", "off"); err != nil {
		t.Fatal(err)
	}
	post(agentEvent{Agent: "claude", Kind: "prompt", Session: s})
	next() // silent task_started
	if out := post(agentEvent{Agent: "claude", Kind: "stop", Session: s}); out["visibility"] != "banner" {
		t.Fatal("setting not applied without restart", out)
	}
	next()
	if out := post(agentEvent{Agent: "dsh", Kind: "approval", Session: sessionKey("dsh", "x")}); out["queued"] != true {
		t.Fatal(out)
	}
	if f := next(); f["status"] != "attention" || f["category"] != "approval_required" {
		t.Fatal(f)
	}
	resp, err := client.Post("http://local/v1/agent-events", "application/json", strings.NewReader(`{"agent":"claude","kind":"stop","session":"`+s+`","transcript":"leak"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("unknown field accepted")
	}
}

// Questions asked through a tool reach the phone when they are asked
// (Codex request_user_input(_async), Claude AskUserQuestion), 2026-11-05.
func TestQuestionToolEvents(t *testing.T) {
	tmux := func(k string) string {
		if k == "TMUX" {
			return "/tmp/tmux"
		}
		return ""
	}
	for _, tc := range []struct{ raw, title, body string }{
		{`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"request_user_input_async","tool_input":{"questions":[{"title":"手机上有哪个视频平台的会员？","options":["有会员","没有会员"]}]}}`, "手机上有哪个视频平台的会员？", "1. 有会员\n2. 没有会员"},
		{`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"request_user_input_async","tool_input":{"questions":[{"title":"Which mailbox?"}]}}`, "Which mailbox?", ""},
		{`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"request_user_input","tool_input":{"questions":[{"id":"c","header":"Continue","question":"Continue?","options":[{"label":"Yes (Recommended)","description":"Run it."},{"label":"No","description":"Stop."}]}]}}`, "Continue?", "1. Yes (Recommended)\n2. No"},
		{`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"AskUserQuestion","tool_input":{"questions":[{"question":"Which DB?","header":"DB","options":[{"label":"Postgres"},{"label":"SQLite"}],"multiSelect":false},{"question":"Cache?","options":[{"label":"Yes"}]}]}}`, "2 questions", "1. Which DB?\n2. Cache?"},
	} {
		h, ok := notifier.ParseHook([]byte(tc.raw))
		if !ok {
			t.Fatal(tc.raw)
		}
		e, ok := agentEventFromHook("codex", h, tmux)
		if !ok || e.Kind != "question" || e.Title != tc.title || e.Body != tc.body || !e.valid() {
			t.Fatalf("%s: %+v %v", tc.raw, e, ok)
		}
	}
	for _, raw := range []string{
		`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"exec_command","tool_input":{"cmd":"ls"}}`,
		`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"request_user_input_async","tool_input":{"questions":[]}}`,
		`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"request_user_input_async","tool_input":"bad"}`,
	} {
		h, _ := notifier.ParseHook([]byte(raw))
		if _, ok := agentEventFromHook("codex", h, tmux); ok {
			t.Fatalf("not a question event: %s", raw)
		}
	}
}

func TestOpenQuestionSurvivesStopUntilAnswered(t *testing.T) {
	tr, now := newTracker(), time.Unix(1800000000, 0)
	s := settings{TurnCompletePush: "all", RateLimitPerMinute: 60}
	key := sessionKey("codex", "s")
	ev := func(kind, title, body string) agentEvent {
		return agentEvent{Agent: "codex", Session: key, Kind: kind, Title: title, Body: body, Mux: "tmux"}
	}
	tr.decide(ev("prompt", "", "set up the reports"), s, now)
	q := tr.decide(ev("question", "Which mailbox?", "1. Work\n2. Home"), s, now.Add(time.Second))
	if q.Status != "attention" || q.Details.Category != "question" || q.Details.Visibility != "banner" || q.Details.Title != "Which mailbox?" {
		t.Fatalf("question: %+v %+v", q, q.Details)
	}
	stop := tr.decide(ev("stop", "I asked which mailbox.", ""), s, now.Add(2*time.Second))
	if stop.Status != "attention" || stop.Details.Category != "question" || stop.Details.Visibility != "silent" ||
		stop.Details.Title != "Which mailbox?" || stop.Details.Body != "1. Work\n2. Home" {
		t.Fatalf("async question turn end must stay waiting: %+v %+v", stop, stop.Details)
	}
	tr.decide(ev("prompt", "Answered: Which mailbox?", "Work"), s, now.Add(3*time.Second))
	done := tr.decide(ev("stop", "Reports go to Work.", ""), s, now.Add(4*time.Second))
	if done.Status != "completed" || done.Details.Category != "task_complete" {
		t.Fatalf("answered: %+v %+v", done, done.Details)
	}
	// Claude: AskUserQuestion, then an elicitation notification without text.
	ck := sessionKey("claude", "c")
	tr.decide(agentEvent{Agent: "claude", Session: ck, Kind: "question", Title: "Which DB?", Body: "1. Postgres"}, s, now)
	el := tr.decide(agentEvent{Agent: "claude", Session: ck, Kind: "question"}, s, now.Add(time.Second))
	if el.Details.Title != "Which DB?" || el.Details.Body != "1. Postgres" || el.Details.Visibility != "silent" {
		t.Fatalf("elicitation keeps the question, no second banner: %+v", el.Details)
	}
}
