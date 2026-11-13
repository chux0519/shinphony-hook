package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net.potafree/shinphony/hook/internal/notifier"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJobsPersistAndReportInterruptions(t *testing.T) {
	q := testQueue(t)
	if err := q.initJobs(); err != nil {
		t.Fatal(err)
	}
	j := setupRequest{"j", "codex", "p", "sandbox", "host"}
	r, err := q.submit(j)
	if err != nil || r.State != "queued" {
		t.Fatal(r, err)
	}
	if _, err = q.submit(j); err != nil {
		t.Fatal("idempotence", err)
	}
	other := j
	other.Agent = "claude"
	if _, err = q.submit(other); err == nil {
		t.Fatal("conflicting request accepted")
	}
	if ok, err := q.processJob(func(setupRequest) error { return errors.New("existing_codex_notify") }); !ok || err != nil {
		t.Fatal(ok, err)
	}
	r, _ = q.job(j.ID)
	if r.State != "failed" || r.Code != "existing_codex_notify" {
		t.Fatal(r)
	}
	q.setJob(j.ID, "running", "")
	if err = q.initJobs(); err != nil {
		t.Fatal(err)
	}
	r, _ = q.job(j.ID)
	if r.State != "interrupted" {
		t.Fatal(r)
	}
}

func TestAsyncSetupAndHooks(t *testing.T) {
	// Hermetic: never start a real codex app-server from tests.
	defer func(old func() (int, int, error)) { checkCodexHooks = old }(checkCodexHooks)
	checkCodexHooks = func() (int, int, error) { return 0, 0, errors.New("codex_not_found") }
	home := privateTemp(t)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "claude"))
	t.Setenv("DSH_HOME", filepath.Join(home, "dsh"))
	dir := filepath.Join(home, "state")
	creds := filepath.Join(home, "credentials")
	os.Mkdir(dir, 0700)
	manager := notifier.Manager{Directory: creds, Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"hostId":"host","hostToken":"` + strings.Repeat("a", 43) + `"}`)), Header: make(http.Header)}, nil
	})}
	if err := manager.Pair("phone", "sandbox", "host", strings.Repeat("b", 43)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, dir, func(context.Context, Event) result { return result{Code: "accepted"} }, creds)
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
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
	for _, agent := range []string{"codex", "claude", "dsh"} {
		payload, _ := json.Marshal(setupRequest{"setup-" + agent, agent, "phone", "sandbox", "host"})
		resp, err := client.Post("http://local/v1/setup", "application/json", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		var accepted setupResult
		json.NewDecoder(resp.Body).Decode(&accepted)
		resp.Body.Close()
		if accepted.State != "queued" {
			t.Fatal(accepted)
		}
		deadline = time.Now().Add(5 * time.Second)
		for {
			resp, err = client.Get("http://local/v1/setup/setup-" + agent)
			if err != nil {
				t.Fatal(err)
			}
			var status setupResult
			json.NewDecoder(resp.Body).Decode(&status)
			resp.Body.Close()
			if status.State == "succeeded" {
				break
			}
			if status.State == "failed" || time.Now().After(deadline) {
				t.Fatal(status)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	for _, path := range []string{filepath.Join(home, "codex", "config.toml"), filepath.Join(home, "claude", "settings.json"), filepath.Join(creds, "dsh-hooks.json")} {
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), managedPrefix) {
			t.Fatal("missing immutable hook", err)
		}
	}
	if err := postHook(ctx, dir, hookEvent{ID: "codex-turn", Status: "completed"}); err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get("http://local/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	var before struct {
		Queue map[string]int `json:"queue"`
	}
	json.NewDecoder(resp.Body).Decode(&before)
	resp.Body.Close()
	for _, n := range before.Queue {
		if n != 0 {
			t.Fatal("setup or turn generated notification", before)
		}
	}
	// Without terminal context an explicit task is still sent, without a preview.
	result, err := postHookResult(ctx, dir, hookEvent{ID: "actual-task", Status: "completed", Trigger: "explicit-task"})
	if err != nil || result.ContextStatus != "unavailable" || result.Destinations == nil || *result.Destinations != 1 || result.Queued == nil || !*result.Queued {
		t.Fatalf("wrong daemon acceptance: %+v %v", result, err)
	}
	resp, err = client.Post("http://local/v1/hooks", "application/json", strings.NewReader(`{"eventId":"x","status":"completed","transcript":"private"}`))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("unexpected content accepted")
	}
	for _, tc := range []struct {
		host   string
		status int
	}{{"wrong", 409}, {"host", 200}, {"host", 200}} {
		resp, err = client.Post("http://local/v1/reset-profile", "application/json", strings.NewReader(`{"profile":"phone","lane":"sandbox","hostId":"`+tc.host+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("reset %s: %d %s", tc.host, resp.StatusCode, data)
		}
	}
	if paired, err := manager.Paired("phone", "sandbox", "host"); err != nil || paired {
		t.Fatal("reset did not clear pairing", paired, err)
	}
	if err := manager.Pair("phone", "sandbox", "host", strings.Repeat("b", 43)); err != nil {
		t.Fatal("re-pair", err)
	}
}

func TestCodexHooksNeedReview(t *testing.T) {
	defer func(old func() (int, int, error)) { checkCodexHooks = old }(checkCodexHooks)
	q, err := openQueue(filepath.Join(privateTemp(t), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.db.Close()
	if _, err = q.submit(setupRequest{"j1", "codex", "p", "sandbox", "host"}); err != nil {
		t.Fatal(err)
	}
	if _, err = q.processJob(func(setupRequest) error { return setupNotice("codex_hooks_need_review") }); err != nil {
		t.Fatal(err)
	}
	if r, _ := q.job("j1"); r.State != "succeeded" || r.Code != "codex_hooks_need_review" {
		t.Fatal(r)
	}
}
