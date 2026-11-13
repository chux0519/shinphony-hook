package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"net.potafree/shinphony/hook/internal/notifier"
)

func TestNotifyRequestMapping(t *testing.T) {
	status, d := notifyRequest{Title: "Build failed", Source: "ci", Error: true}.details()
	if status != "failed" || d.Category != "error" || d.Project != "ci" || d.Visibility != "banner" {
		t.Fatal(status, d)
	}
	if _, d = (notifyRequest{Body: "x", Silent: true}).details(); d.Visibility != "silent" || d.Category != "task_complete" {
		t.Fatal(d)
	}
	if (notifyRequest{EventID: "e"}).valid() || (notifyRequest{EventID: "e", Title: strings.Repeat("x", 81)}).valid() {
		t.Fatal("empty or unbounded notification accepted")
	}
}

// A daemon whose sender accepts or rejects, and the real CLI against it.
func notifyFixture(t *testing.T, code string) (dir string, sent func() []map[string]any) {
	home := privateTemp(t)
	t.Setenv("HOME", home)
	dir = filepath.Join(home, "state")
	creds := filepath.Join(home, "credentials")
	os.Mkdir(dir, 0700)
	manager := notifier.Manager{Directory: creds, Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"hostId":"host","hostToken":"` + strings.Repeat("a", 43) + `"}`)), Header: make(http.Header)}, nil
	})}
	if err := manager.Pair("phone", "sandbox", "host", strings.Repeat("b", 43)); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []map[string]any
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, dir, func(c context.Context, e Event) result {
			f := map[string]any{"status": e.Status}
			if d, ok := c.Value(agentDetailsKey{}).(json.RawMessage); ok {
				json.Unmarshal(d, &f)
			}
			mu.Lock()
			got = append(got, f)
			mu.Unlock()
			return result{Code: code}
		}, creds)
	}()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 200; i++ {
		if c, err := dialLocal(context.Background(), dir); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return dir, func() []map[string]any { mu.Lock(); defer mu.Unlock(); return append([]map[string]any(nil), got...) }
}

func TestNotifyCLI(t *testing.T) {
	dir, sent := notifyFixture(t, "accepted")
	var stderr bytes.Buffer
	if code := notifyCLI(dir, []string{"--strict", "--source", "backup", "Backup done"}, strings.NewReader(""), &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	if code := notifyCLI(dir, []string{"--error"}, strings.NewReader("Deploy failed\nexit status 2\n"), &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(sent()) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	got := sent()
	if len(got) != 2 || got[0]["title"] != "Backup done" || got[0]["project"] != "backup" || got[0]["status"] != "completed" {
		t.Fatal(got)
	}
	if got[1]["title"] != "Deploy failed" || got[1]["body"] != "exit status 2" || got[1]["category"] != "error" || got[1]["status"] != "failed" {
		t.Fatal(got[1])
	}
	if code := notifyCLI(dir, nil, strings.NewReader(""), &stderr); code != 2 {
		t.Fatal("empty message", code)
	}
}

func TestNotifyStrictFailure(t *testing.T) {
	dir, _ := notifyFixture(t, "http_401")
	var stderr bytes.Buffer
	if code := notifyCLI(dir, []string{"--strict", "x"}, strings.NewReader(""), &stderr); code != 1 || !strings.Contains(stderr.String(), "http_401") {
		t.Fatal(code, stderr.String())
	}
	// Best effort never fails the calling script.
	if code := notifyCLI(dir, []string{"x"}, strings.NewReader(""), &stderr); code != 0 {
		t.Fatal(code)
	}
}

func TestNotifyWithoutDaemon(t *testing.T) {
	dir := privateTemp(t)
	var stderr bytes.Buffer
	if code := notifyCLI(dir, []string{"x"}, strings.NewReader(""), &stderr); code != 0 || !strings.Contains(stderr.String(), "not running") {
		t.Fatal(code, stderr.String())
	}
	if code := notifyCLI(dir, []string{"--strict", "x"}, strings.NewReader(""), &stderr); code != 1 {
		t.Fatal(code)
	}
}
