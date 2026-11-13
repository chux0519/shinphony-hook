package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if err := privateUmask(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func testQueue(t *testing.T) *queue {
	t.Helper()
	q, e := openQueue(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { q.db.Close() })
	return q
}

func privateTemp(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "private")
	if err = prepareDir(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}
func TestDurableQueue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	q, err := openQueue(path)
	if err != nil {
		t.Fatal(err)
	}
	e := Event{"phone", "turn1", "completed"}
	if ok, err := q.enqueue(e, 1000); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, err := q.enqueue(e, 1001); ok || err != nil {
		t.Fatal("dedup", ok, err)
	}
	if _, err = q.enqueue(Event{"phone", "turn1", "failed"}, 1001); err == nil {
		t.Fatal("conflict accepted")
	}
	i, err := q.next(1001)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.reserve(i, 1001); err != nil {
		t.Fatal(err)
	}
	q.db.Close()
	q, err = openQueue(path)
	if err != nil {
		t.Fatal(err)
	}
	defer q.db.Close()
	if _, err = q.next(1002); err != sql.ErrNoRows {
		t.Fatal("lease missing", err)
	}
	i, err = q.next(1032)
	if err != nil || i.Attempts != 1 {
		t.Fatal("restart recovery", i, err)
	}
	if err = q.finish(i, 1032, result{Code: "accepted"}); err != nil {
		t.Fatal(err)
	}
	counts, _ := q.counts()
	if counts["sent"] != 1 {
		t.Fatal(counts)
	}
}
func TestRetryExpiryAndCapacity(t *testing.T) {
	q := testQueue(t)
	e := Event{"phone", "retry", "attention"}
	q.enqueue(e, 1000)
	now := int64(1000)
	for n := 0; n < 8; n++ {
		i, err := q.next(now)
		if err != nil {
			t.Fatal(err)
		}
		if err = q.reserve(i, now); err != nil {
			t.Fatal(err)
		}
		if err = q.finish(i, now, result{Code: "http_503", Retry: true, After: time.Second}); err != nil {
			t.Fatal(err)
		}
		now++
	}
	counts, _ := q.counts()
	if counts["failed"] != 1 {
		t.Fatal(counts)
	}
	q.enqueue(Event{"phone", "expired", "completed"}, 1000)
	if _, err := q.next(1000 + 86400); err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if _, err := q.enqueue(Event{"../escape", "bad", "completed"}, now); err == nil {
		t.Fatal("unsafe ID")
	}
	tx, _ := q.db.Begin()
	for n := 0; n < maxRows; n++ {
		_, err := tx.Exec("INSERT OR IGNORE INTO outbox(profile,event_id,status,created,next_at) VALUES('load',?,'completed',?,?)", n, now, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	tx.Commit()
	if _, err := q.enqueue(Event{"phone", "overflow", "completed"}, now); err == nil {
		t.Fatal("unbounded queue")
	}
}
func TestServiceIPC(t *testing.T) {
	dir := privateTemp(t)
	os.Chmod(dir, 0700)
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
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialLocal(ctx, dir)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("http://local/v1/status")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if unlock, err := lockDir(dir); err == nil {
		unlock()
		t.Fatal("second service allowed")
	}
	for _, raw := range []string{`{"profile":"p","eventId":"e","status":"completed"}`, `{"profile":"p","eventId":"e","status":"completed"}`} {
		resp, err := client.Post("http://local/v1/events", "application/json", strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}
	}
	resp, err := client.Post("http://local/v1/events", "application/json", strings.NewReader(`{"profile":"p","eventId":"x","status":"completed","transcript":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("unexpected fields accepted")
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		resp, err = client.Get("http://local/v1/status")
		if err != nil {
			t.Fatal(err)
		}
		var s struct{ Queue map[string]int }
		err = json.NewDecoder(resp.Body).Decode(&s)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if s.Queue["sent"] == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(s)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestDelivery(t *testing.T) {
	dir := privateTemp(t)
	os.Chmod(dir, 0700)
	os.WriteFile(filepath.Join(dir, "phone.json"), []byte(`{"schema":1,"lane":"testflight","hostId":"host","hostToken":"`+strings.Repeat("a", 43)+`"}`), 0600)
	for _, test := range []struct {
		code  int
		body  string
		retry bool
		want  string
	}{{200, `{"accepted":true}`, false, "accepted"}, {202, `{"accepted":true}`, false, "accepted"}, {202, `{}`, true, "invalid_response"}, {401, `secret`, false, "http_401"}, {429, ``, true, "http_429"}, {503, ``, true, "http_503"}, {200, `{}`, true, "invalid_response"}} {
		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://notify.potafree.net/testflight/v1/events" {
				t.Error(r.URL)
			}
			data, _ := io.ReadAll(r.Body)
			if strings.Contains(string(data), "profile") {
				t.Error("profile leaked")
			}
			return &http.Response{StatusCode: test.code, Header: http.Header{"Retry-After": []string{"120"}}, Body: io.NopCloser(strings.NewReader(test.body))}, nil
		})}
		r := deliver(dir, client)(context.Background(), Event{"phone", "event", "completed"})
		if r.Code != test.want || r.Retry != test.retry {
			t.Fatal(r)
		}
	}
}
func TestDeliveryDetails(t *testing.T) {
	dir := privateTemp(t)
	os.Chmod(dir, 0700)
	os.WriteFile(filepath.Join(dir, "phone.json"), []byte(`{"schema":1,"lane":"sandbox","hostId":"host","hostToken":"`+strings.Repeat("a", 43)+`"}`), 0600)
	var got map[string]any
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		json.NewDecoder(r.Body).Decode(&got)
		return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(`{"accepted":true}`))}, nil
	})}
	// Details can never override the event identity.
	details := json.RawMessage(`{"category":"task_complete","agent":"dsh","session":"` + strings.Repeat("f", 32) + `","title":"done","visibility":"silent","eventId":"forged","status":"failed"}`)
	ctx := context.WithValue(context.Background(), agentDetailsKey{}, details)
	if r := deliver(dir, client)(ctx, Event{"phone", "event", "completed"}); r.Code != "accepted" {
		t.Fatal(r)
	}
	if got["eventId"] != "event" || got["status"] != "completed" || got["category"] != "task_complete" || got["visibility"] != "silent" || got["agent"] != "dsh" {
		t.Fatal(got)
	}
	// An old relay rejects the v2 fields: banners fall back to v1, silent
	// events are dropped instead of turning into banners.
	for _, vis := range []string{"banner", "silent"} {
		var bodies []map[string]any
		old := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			var b map[string]any
			json.NewDecoder(r.Body).Decode(&b)
			bodies = append(bodies, b)
			if len(b) > 2 {
				return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{"error":"invalid_fields"}`))}, nil
			}
			return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(`{"accepted":true}`))}, nil
		})}
		d := json.RawMessage(`{"category":"task_complete","visibility":"` + vis + `"}`)
		r := deliver(dir, old)(context.WithValue(context.Background(), agentDetailsKey{}, d), Event{"phone", "e-" + vis, "completed"})
		if vis == "banner" && (r.Code != "accepted" || len(bodies) != 2 || len(bodies[1]) != 2) {
			t.Fatal(r, bodies)
		}
		if vis == "silent" && (r.Code != "relay_v1_silent_dropped" || r.Retry || len(bodies) != 1) {
			t.Fatal(r, bodies)
		}
	}
	// v1 events keep the old body.
	got = nil
	if r := deliver(dir, client)(context.Background(), Event{"phone", "event2", "attention"}); r.Code != "accepted" || len(got) != 2 {
		t.Fatal(got)
	}
}
func TestUnsafeState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode/symlink checks; Windows ACL checked separately")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "linked")
	os.Symlink(filepath.Join(dir, "missing"), path)
	if err := prepareDir(path); err == nil {
		t.Fatal("symlink accepted")
	}
	f := filepath.Join(dir, "public")
	os.WriteFile(f, []byte("secret"), 0644)
	os.Chmod(f, 0644)
	if err := privatePath(f, false); err == nil {
		t.Fatal("public credentials accepted")
	}
}

func TestWorkerRecoversTransientFailure(t *testing.T) {
	q := testQueue(t)
	_, err := q.enqueue(Event{"p", "retry-success", "completed"}, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	done := make(chan error, 1)
	go func() {
		done <- worker(ctx, q, func(context.Context, Event) result {
			calls++
			if calls == 1 {
				return result{Code: "http_429", Retry: true, After: time.Second}
			}
			return result{Code: "accepted"}
		}, make(chan struct{}))
	}()
	deadline := time.Now().Add(6 * time.Second)
	for {
		counts, err := q.counts()
		if err != nil {
			t.Fatal(err)
		}
		if counts["sent"] == 1 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("retry did not finish", counts)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("unexpected attempts", calls)
	}
	var attempts int
	q.db.QueryRow("SELECT attempts FROM outbox WHERE event_id='retry-success'").Scan(&attempts)
	if attempts != 2 {
		t.Fatal(attempts)
	}
}

func TestFutureSchemaRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	q, err := openQueue(path)
	if err != nil {
		t.Fatal(err)
	}
	q.db.Exec("PRAGMA user_version=99")
	q.db.Close()
	if q, err = openQueue(path); err == nil {
		q.db.Close()
		t.Fatal("newer schema accepted")
	}
}

func TestImmutableServiceBinary(t *testing.T) {
	dir := privateTemp(t)
	path, err := serviceExecutable(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(path), managedPrefix) {
		t.Fatal("not using the canonical hook executable name", path)
	}
	data, err := os.ReadFile(path)
	if err != nil || !matchesManagedBinary(path, data) {
		t.Fatal("immutable executable identity", err)
	}
	again, err := serviceExecutable(dir)
	if err != nil || again != path {
		t.Fatal("repeat copy", err)
	}
	if err = os.WriteFile(path, []byte("changed"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = serviceExecutable(dir); err == nil {
		t.Fatal("modified binary reused")
	}
}
