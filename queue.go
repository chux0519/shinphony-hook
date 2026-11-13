package main

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Bound undelivered backlog, not the seven-day terminal deduplication history.
const maxRows = 2000

var errQueueFull = errors.New("queue_full")

// Only an identified capacity error crosses IPC; never return raw SQL errors.
func enqueueErrorCode(err error) string {
	if errors.Is(err, errQueueFull) {
		return "queue_full"
	}
	return "enqueue_rejected"
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Event struct {
	Profile string `json:"profile"`
	ID      string `json:"eventId"`
	Status  string `json:"status"`
}

func (e Event) valid() bool {
	return identifier.MatchString(e.Profile) && identifier.MatchString(e.ID) && (e.Status == "completed" || e.Status == "failed" || e.Status == "attention")
}

type item struct {
	Event
	Attempts int
	Created  int64
	Payload  string
}
type queue struct {
	db        *sql.DB
	profileMu sync.Mutex
}

type diagnostic struct {
	State    string `json:"state"`
	Attempts int    `json:"attempts"`
	Code     string `json:"code"`
	Created  int64  `json:"created"`
	Next     int64  `json:"nextAttempt"`
}

func (q *queue) diagnostics() ([]diagnostic, error) {
	rows, err := q.db.Query("SELECT state,attempts,last_code,created,next_at FROM outbox ORDER BY created DESC LIMIT 20")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []diagnostic{}
	for rows.Next() {
		var d diagnostic
		if err = rows.Scan(&d.State, &d.Attempts, &d.Code, &d.Created, &d.Next); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func openQueue(path string) (*queue, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*queue, error) { db.Close(); return nil, e }
	for _, s := range []string{"PRAGMA busy_timeout=3000", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA journal_size_limit=1048576", "PRAGMA max_page_count=4096"} {
		if _, err = db.Exec(s); err != nil {
			return fail(err)
		}
	}
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if version > 2 {
		return fail(errors.New("unsupported_schema"))
	}
	tx, err := db.Begin()
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	for _, s := range []string{`CREATE TABLE IF NOT EXISTS outbox (
 profile TEXT NOT NULL, event_id TEXT NOT NULL, status TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
 created INTEGER NOT NULL, next_at INTEGER NOT NULL, last_code TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(profile,event_id))`, `CREATE INDEX IF NOT EXISTS due ON outbox(state,next_at)`,
		`CREATE TABLE IF NOT EXISTS setup_jobs(id TEXT PRIMARY KEY, agent TEXT NOT NULL, profile TEXT NOT NULL, lane TEXT NOT NULL, host TEXT NOT NULL, state TEXT NOT NULL, code TEXT NOT NULL, updated INTEGER NOT NULL)`, "PRAGMA user_version=2"} {
		if _, err = tx.Exec(s); err != nil {
			return fail(err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fail(err)
	}
	// Added without a schema bump: older binaries name their columns and
	// leave it NULL.
	var hasPayload int
	if err = db.QueryRow("SELECT count(*) FROM pragma_table_info('outbox') WHERE name='payload'").Scan(&hasPayload); err != nil {
		return fail(err)
	}
	if hasPayload == 0 {
		if _, err = db.Exec("ALTER TABLE outbox ADD COLUMN payload TEXT"); err != nil {
			return fail(err)
		}
	}
	q := &queue{db: db}
	if err = q.initContexts(); err != nil {
		return fail(err)
	}
	if err = q.migrateTaskSemantics(); err != nil {
		return fail(err)
	}
	return q, nil
}

func (q *queue) migrateTaskSemantics() error {
	tx, err := q.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("CREATE TABLE IF NOT EXISTS task_semantics(version INTEGER PRIMARY KEY)"); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow("SELECT count(*) FROM task_semantics WHERE version=1").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		// Legacy queued completions cannot be distinguished from turn callbacks.
		// Suppress once on migration rather than replaying noise after upgrading.
		if _, err = tx.Exec("UPDATE outbox SET state='suppressed',last_code='legacy_turn_disabled' WHERE state='pending' AND status='completed'"); err != nil {
			return err
		}
		if _, err = tx.Exec("INSERT INTO task_semantics(version) VALUES(1)"); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (q *queue) enqueue(e Event, now int64) (bool, error) { return q.enqueueWith(e, "", now) }

// enqueueWith stores the event with its v2 relay details (JSON, may be empty).
func (q *queue) enqueueWith(e Event, payload string, now int64) (bool, error) {
	if !e.valid() || len(payload) > 2048 {
		return false, errors.New("invalid_event")
	}
	tx, err := q.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var old string
	err = tx.QueryRow("SELECT status FROM outbox WHERE profile=? AND event_id=?", e.Profile, e.ID).Scan(&old)
	if err == nil {
		if old != e.Status {
			return false, errors.New("event_conflict")
		}
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	// Retention also bounds deduplication: event IDs are remembered for seven days.
	if _, err = tx.Exec("DELETE FROM outbox WHERE created<? AND state IN ('sent','failed','suppressed')", now-7*86400); err != nil {
		return false, err
	}
	var count int
	if err = tx.QueryRow("SELECT count(*) FROM outbox WHERE state='pending'").Scan(&count); err != nil {
		return false, err
	}
	if count >= maxRows {
		return false, errQueueFull
	}
	_, err = tx.Exec("INSERT INTO outbox(profile,event_id,status,created,next_at,payload) VALUES(?,?,?,?,?,NULLIF(?,''))", e.Profile, e.ID, e.Status, now, now, payload)
	if err != nil {
		return false, err
	}
	return true, tx.Commit()
}
func (q *queue) next(now int64) (item, error) {
	var i item
	// Expiration applies even if Retry-After postponed the next attempt.
	if _, err := q.db.Exec("UPDATE outbox SET state='failed',last_code='expired' WHERE state='pending' AND created<=?", now-86400); err != nil {
		return i, err
	}
	var payload sql.NullString
	err := q.db.QueryRow("SELECT profile,event_id,status,attempts,created,payload FROM outbox WHERE state='pending' AND next_at<=? ORDER BY next_at,created LIMIT 1", now).Scan(&i.Profile, &i.ID, &i.Status, &i.Attempts, &i.Created, &payload)
	i.Payload = payload.String
	return i, err
}

// Reserve an attempt durably BEFORE the request. A crash consumes an attempt,
// preventing endless retries on repeated crashes; no permanent processing state.
func (q *queue) reserve(i item, now int64) error {
	_, err := q.db.Exec("UPDATE outbox SET attempts=attempts+1,next_at=? WHERE profile=? AND event_id=?", now+30, i.Profile, i.ID)
	return err
}
func (q *queue) finish(i item, now int64, r result) error {
	state := "pending"
	if r.Code == "accepted" {
		state = "sent"
	} else if r.Code == "actively_viewing" {
		state = "suppressed"
	} else if !r.Retry || i.Attempts+1 >= 8 {
		state = "failed"
	}
	delay := r.After
	if delay < time.Second {
		delay = time.Duration(1<<min(i.Attempts+1, 10)) * time.Second
	}
	if delay > 24*time.Hour {
		delay = 24 * time.Hour
	}
	_, err := q.db.Exec("UPDATE outbox SET state=?,next_at=?,last_code=? WHERE profile=? AND event_id=?", state, now+int64(delay/time.Second), r.Code, i.Profile, i.ID)
	return err
}

// eventState summarises one event over its destinations: sent once any
// phone's relay accepted it, failed once all gave up, pending otherwise.
func (q *queue) eventState(id string) (state, code string, err error) {
	rows, err := q.db.Query("SELECT state,last_code FROM outbox WHERE event_id=?", id)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	n, done := 0, 0
	for rows.Next() {
		var s, c string
		if err = rows.Scan(&s, &c); err != nil {
			return "", "", err
		}
		n++
		if s == "sent" {
			return "sent", c, nil
		}
		if s == "failed" || s == "suppressed" {
			done, state, code = done+1, s, c
		}
	}
	if n == 0 {
		return "", "", sql.ErrNoRows
	}
	if done < n {
		return "pending", "", rows.Err()
	}
	return state, code, rows.Err()
}

func (q *queue) counts() (map[string]int, error) {
	rows, err := q.db.Query("SELECT state,count(*) FROM outbox GROUP BY state")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int{"pending": 0, "sent": 0, "failed": 0}
	for rows.Next() {
		var s string
		var n int
		if err = rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		m[s] = n
	}
	return m, rows.Err()
}
func (q *queue) maintain(now int64) error {
	if _, err := q.db.Exec("DELETE FROM hc_presence WHERE expires<=?", now); err != nil {
		return err
	}
	if _, err := q.db.Exec("DELETE FROM task_presence WHERE expires<=?", now); err != nil {
		return err
	}
	for _, table := range []string{"task_contexts", "task_context_events"} {
		if _, err := q.db.Exec("DELETE FROM "+table+" WHERE updated<?", now-86400); err != nil {
			return err
		}
	}
	if _, err := q.db.Exec("DELETE FROM outbox WHERE created<? AND state IN ('sent','failed','suppressed')", now-7*86400); err != nil {
		return err
	}
	_, err := q.db.Exec("PRAGMA wal_checkpoint(PASSIVE)")
	return err
}
func safeDBError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("storage_unavailable")
}
