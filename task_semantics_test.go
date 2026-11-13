package main

import (
	"strings"
	"testing"

	"net.potafree/shinphony/hook/internal/notifier"
)

func TestTurnCallbacksAreNeverTasks(t *testing.T) {
	for _, kind := range []string{"codex-notify-all", "claude-hook-all"} {
		for _, raw := range []string{`{"type":"agent-turn-complete","thread-id":"s","turn-id":"t"}`, `{"hook_event_name":"Stop","session_id":"s","turn_id":"t"}`} {
			if _, _, ok := notifier.Extract(kind, []byte(raw)); ok {
				t.Fatal("turn produced event", kind)
			}
		}
	}
}
func TestLegacyQueueMigrationOnce(t *testing.T) {
	q := testQueue(t)
	q.db.Exec("DELETE FROM task_semantics")
	q.enqueue(Event{"p", "old", "completed"}, 1)
	q.enqueue(Event{"p", "approval", "attention"}, 1)
	if err := q.migrateTaskSemantics(); err != nil {
		t.Fatal(err)
	}
	var state string
	q.db.QueryRow("SELECT state FROM outbox WHERE event_id='old'").Scan(&state)
	if state != "suppressed" {
		t.Fatal(state)
	}
	q.enqueue(Event{"p", "new", "completed"}, 2)
	if err := q.migrateTaskSemantics(); err != nil {
		t.Fatal(err)
	}
	q.db.QueryRow("SELECT state FROM outbox WHERE event_id='new'").Scan(&state)
	if state != "pending" {
		t.Fatal("new explicit task lost", state)
	}
	q.db.QueryRow("SELECT state FROM outbox WHERE event_id='approval'").Scan(&state)
	if state != "pending" {
		t.Fatal("approval lost", state)
	}
}
func TestExplicitTaskRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{`{}`, `{"taskId":"../x","status":"completed"}`, `{"taskId":"x","status":"completed","content":"secret"}`, strings.Repeat("x", 5000)} {
		if err := explicitTaskEvent(privateTemp(t), strings.NewReader(input)); err == nil || err.Error() != "invalid_task_event" {
			t.Fatal(input, err)
		}
	}
}
