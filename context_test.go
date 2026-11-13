package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func sampleContext(event, thread string) *localSnapshot {
	return &localSnapshot{taskContext: taskContext{Version: 1, Agent: "codex", Thread: thread, Title: "验证移动端", Multiplexer: "tmux", Session: "term", Window: "agent", Preview: "result", Route: event, Binary: strings.Repeat("a", 64)}, Socket: "/tmp/test", ServerPID: "123", PaneID: "%1"}
}
func TestContextLatestAndThreadIsolation(t *testing.T) {
	q := testQueue(t)
	now := time.Now().Unix()
	if e := q.saveContext(sampleContext("event1", "thread1"), now); e != nil {
		t.Fatal(e)
	}
	if c := q.contextForEvent("event1"); c == nil || c.Preview != "result" {
		t.Fatal(c)
	}
	if e := q.saveContext(sampleContext("event2", "thread1"), now); e != nil {
		t.Fatal(e)
	}
	if c := q.contextForEvent("event1"); c == nil || c.Preview != "" {
		t.Fatal("old event inherited new output")
	}
	q.saveContext(sampleContext("event3", "thread2"), now)
	if q.contextForEvent("event1") != nil {
		t.Fatal("old thread routed to replacement")
	}
	var count int
	q.db.QueryRow("SELECT count(*) FROM task_contexts").Scan(&count)
	if count != 1 {
		t.Fatal("not overwritten")
	}
	q.maintain(now + 86401)
	if q.contextForEvent("event3") != nil {
		t.Fatal("retained expired content")
	}
}
func TestContextProjectionAndTextBounds(t *testing.T) {
	c := sampleContext("event", "thread")
	raw, _ := json.Marshal(c.taskContext)
	if strings.Contains(string(raw), "socket") || strings.Contains(string(raw), "Pid") {
		t.Fatal("private routing leaked")
	}
	s := cleanText(strings.Repeat("中文", 500)+"\x00", 700)
	if len(s) > 700 || !utf8.ValidString(s) {
		t.Fatal("invalid limit")
	}
	if cleanLabel("a\nb\tc\x00", 120) != "a b c" {
		t.Fatal("label controls")
	}
	if captureContext(context.Background(), &hookSource{Agent: "unknown"}, "event", "") != nil {
		t.Fatal("unknown adapter")
	}
}
func TestPresenceWithoutPreviewToggle(t *testing.T) {
	q := testQueue(t)
	mux := http.NewServeMux()
	q.registerContexts(mux)
	q.registerPresence(mux)
	request := func(path, body string) int {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	if request("/v1/context-policy", `{"preview":false}`) != 404 {
		t.Fatal("obsolete preview toggle remains")
	}
	if request("/v1/presence", `{"profile":"phone","tty":"/dev/ttys001","active":true}`) != 200 {
		t.Fatal("presence")
	}
	if request("/v1/presence", `{"profile":"phone","tty":"; rm", "active":true}`) != 400 {
		t.Fatal("unsafe tty")
	}
	if request("/v1/presence", `{"profile":"phone","tty":"/dev/ttys001","active":false}`) != 200 {
		t.Fatal("clear")
	}
	var n int
	q.db.QueryRow("SELECT count(*) FROM task_presence").Scan(&n)
	if n != 0 {
		t.Fatal("lease not removed")
	}
}
