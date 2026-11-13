package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func seedCapacityRows(t *testing.T, q *queue, count int, state string, now int64) {
	t.Helper()
	tx, err := q.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare("INSERT INTO outbox(profile,event_id,status,state,created,next_at) VALUES('history',?,'completed',?,?,?)")
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	for n := 0; n < count; n++ {
		rowState := state
		if state == "terminal-mix" {
			rowState = "sent"
			if n >= 1967 {
				rowState = "failed"
			}
		}
		if _, err = stmt.Exec(fmt.Sprintf("row-%d", n), rowState, now-60, now+3600); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestQueueCapacityExcludesRetainedHistory(t *testing.T) {
	for _, state := range []string{"terminal-mix", "suppressed"} {
		t.Run(state, func(t *testing.T) {
			q := testQueue(t)
			now := int64(10 * 86400)
			seedCapacityRows(t, q, maxRows, state, now)
			if inserted, err := q.enqueue(Event{"fixture", "new-event", "completed"}, now); !inserted || err != nil {
				t.Fatalf("retained history blocked a new event: inserted=%v err=%v", inserted, err)
			}
			counts, err := q.counts()
			if err != nil {
				t.Fatal(err)
			}
			if counts["pending"] != 1 {
				t.Fatal("new event not pending", counts)
			}
			var history int
			if err = q.db.QueryRow("SELECT count(*) FROM outbox WHERE profile='history'").Scan(&history); err != nil || history != maxRows {
				t.Fatalf("history changed: count=%d err=%v", history, err)
			}
			if state == "terminal-mix" && (counts["sent"] != 1967 || counts["failed"] != 33) {
				t.Fatal("terminal history was deleted", counts)
			}
		})
	}
}

func TestQueuePendingCapacityPreservesDedupConflictAndLease(t *testing.T) {
	q := testQueue(t)
	now := int64(10 * 86400)
	seedCapacityRows(t, q, maxRows, "pending", now)
	if inserted, err := q.enqueue(Event{"fixture", "overflow", "completed"}, now); inserted || err == nil || err.Error() != "queue_full" {
		t.Fatalf("pending limit: inserted=%v err=%v", inserted, err)
	}
	if inserted, err := q.enqueue(Event{"history", "row-0", "completed"}, now); inserted || err != nil {
		t.Fatal("duplicate must succeed at capacity", inserted, err)
	}
	if _, err := q.enqueue(Event{"history", "row-0", "failed"}, now); err == nil || err.Error() != "event_conflict" {
		t.Fatal("conflict must remain distinct", err)
	}
	// All retries/leased rows are still pending, including future next_at.
	if _, err := q.db.Exec("UPDATE outbox SET next_at=? WHERE event_id='row-0'", now); err != nil {
		t.Fatal(err)
	}
	item, err := q.next(now)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.reserve(item, now); err != nil {
		t.Fatal(err)
	}
	if err = q.finish(item, now, result{Code: "http_503", Retry: true, After: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err = q.enqueue(Event{"fixture", "still-full", "completed"}, now); err == nil || err.Error() != "queue_full" {
		t.Fatal("retry stopped counting as pending", err)
	}
	item.Attempts++
	if err = q.finish(item, now, result{Code: "accepted"}); err != nil {
		t.Fatal(err)
	}
	if inserted, err := q.enqueue(Event{"fixture", "after-delivery", "completed"}, now); !inserted || err != nil {
		t.Fatal("completed row did not release pending capacity", inserted, err)
	}
}

func TestQueueCapacityConcurrentLastSlot(t *testing.T) {
	q := testQueue(t)
	now := int64(10 * 86400)
	seedCapacityRows(t, q, maxRows-1, "pending", now)
	var group sync.WaitGroup
	results := make(chan bool, 2)
	failures := make(chan error, 2)
	for n := 0; n < 2; n++ {
		group.Add(1)
		go func(n int) {
			defer group.Done()
			ok, err := q.enqueue(Event{"fixture", fmt.Sprintf("concurrent-%d", n), "completed"}, now)
			results <- ok
			failures <- err
		}(n)
	}
	group.Wait()
	close(results)
	close(failures)
	inserted, full := 0, 0
	for ok := range results {
		if ok {
			inserted++
		}
	}
	for err := range failures {
		if err != nil {
			if err.Error() != "queue_full" {
				t.Fatal(err)
			}
			full++
		}
	}
	if inserted != 1 || full != 1 {
		t.Fatal("last slot was not atomic", inserted, full)
	}
	counts, err := q.counts()
	if err != nil || counts["pending"] != maxRows {
		t.Fatal(counts, err)
	}
}

func TestQueueCapacityKeepsSevenDayRetention(t *testing.T) {
	q := testQueue(t)
	now := int64(10 * 86400)
	cutoff := now - 7*86400
	for _, state := range []string{"sent", "failed", "suppressed", "pending"} {
		for _, age := range []struct {
			name    string
			created int64
		}{{"older", cutoff - 1}, {"boundary", cutoff}, {"recent", cutoff + 1}} {
			if _, err := q.db.Exec("INSERT INTO outbox(profile,event_id,status,state,created,next_at) VALUES('fixture',?,'completed',?,?,?)", state+"-"+age.name, state, age.created, now+3600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := q.maintain(now); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"sent", "failed", "suppressed", "pending"} {
		for _, age := range []string{"older", "boundary", "recent"} {
			id := state + "-" + age
			var count int
			if err := q.db.QueryRow("SELECT count(*) FROM outbox WHERE event_id=?", id).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 1
			if age == "older" && state != "pending" {
				want = 0
			}
			if count != want {
				t.Fatal("retention changed", state, age, count)
			}
			if count == 1 {
				if ok, err := q.enqueue(Event{"fixture", id, "completed"}, now); ok || err != nil {
					t.Fatal("retained dedup lost", ok, err)
				}
			}
		}
	}
	if ok, err := q.enqueue(Event{"fixture", "sent-older", "completed"}, now); !ok || err != nil {
		t.Fatal("expired ID could not be reused after maintenance", ok, err)
	}
}

func TestQueueCapacityIPC(t *testing.T) {
	for _, state := range []string{"terminal-mix", "pending"} {
		t.Run(state, func(t *testing.T) {
			dir := privateTemp(t)
			q, err := openQueue(filepath.Join(dir, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			seedCapacityRows(t, q, maxRows, state, time.Now().Unix())
			q.db.Close()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- serve(ctx, dir, func(context.Context, Event) result { return result{Code: "accepted"} })
			}()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			deadline := time.Now().Add(5 * time.Second)
			for {
				response, err := client.Get("http://local/v1/status")
				if err == nil {
					response.Body.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("isolated service did not start", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			response, err := client.Post("http://local/v1/events", "application/json", strings.NewReader(`{"profile":"fixture","eventId":"new-event","status":"completed"}`))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if state == "pending" {
				if response.StatusCode != 409 || strings.TrimSpace(string(body)) != "queue_full" {
					t.Fatalf("capacity IPC diagnostic: HTTP %d code=%q", response.StatusCode, body)
				}
			} else if response.StatusCode != 200 {
				t.Fatalf("retained history rejected by real IPC: HTTP %d code=%q", response.StatusCode, body)
			}
		})
	}
}

func TestQueueCapacityErrorCodeIsSanitized(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{errQueueFull, "queue_full"},
		{fmt.Errorf("private storage detail: %w", errQueueFull), "queue_full"},
		{errors.New("private SQL table or credential detail"), "enqueue_rejected"},
		{errors.New("event_conflict"), "enqueue_rejected"},
	} {
		if got := enqueueErrorCode(test.err); got != test.want {
			t.Fatal("unsafe or incorrect error code", got)
		}
	}
}

func TestQueueCapacityKeepsStorageLimits(t *testing.T) {
	q := testQueue(t)
	for _, test := range []struct {
		pragma string
		want   int64
	}{{"max_page_count", 4096}, {"journal_size_limit", 1048576}} {
		var got int64
		if err := q.db.QueryRow("PRAGMA " + test.pragma).Scan(&got); err != nil || got != test.want {
			t.Fatal(test.pragma, got, err)
		}
	}
}
