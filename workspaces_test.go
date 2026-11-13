package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkspacePathsIsolationAndStaleWrites(t *testing.T) {
	q := testQueue(t)
	current := "first"
	resolve := func(context.Context, string) (*workspaceState, error) {
		return &workspaceState{ID: current, Multiplexer: "tmux", Directory: "/nonexistent-test-fixture"}, nil
	}
	call := func(body string, code int) workspaceState {
		t.Helper()
		w := httptest.NewRecorder()
		q.workspace(w, httptest.NewRequest("POST", "/v1/workspace", strings.NewReader(body)), resolve)
		if w.Code != code {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body.String())
		}
		var state workspaceState
		if code == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
				t.Fatal(err)
			}
		}
		return state
	}
	call(`{"id":"first","files":"/repo/files"}`, 200)
	got := call(`{"id":"first","git":"/repo"}`, 200)
	if got.Files != "/repo/files" || got.Git != "/repo" {
		t.Fatal(got)
	}
	current = "second"
	call(`{"id":"first","files":"/wrong"}`, 409)
	if got := call(`{}`, 200); got.Files != "" || got.Git != "" {
		t.Fatal(got)
	}
	call(`{"id":"second","files":"/other"}`, 200)
	current = "first"
	if got := call(`{}`, 200); got.Files != "/repo/files" || got.Git != "/repo" {
		t.Fatal(got)
	}
	call(`{"files":"/missing-id"}`, 409)
	call(`{"id":"first","files":"relative"}`, 400)
	call(`{"id":"first","git":"/bad\npath"}`, 400)
	call(`{"unknown":true}`, 400)
	// A maliciously shaped absolute path is data, not a shell command.
	call(`{"id":"first","files":"/space dir/$(touch NEVER)"}`, 200)
}

func TestWorkspaceIdentity(t *testing.T) {
	s := &recentSession{Socket: "/tmp/tmux/a", ServerPID: "1", ServerStart: "start1", Session: "$1", Window: "@1", Pane: "%1"}
	id := workspaceID(s)
	s.Pane = "%2"
	s.Window = "@2"
	if workspaceID(s) != id {
		t.Fatal("pane change must retain session workspace")
	}
	s.Session = "$2"
	if workspaceID(s) == id {
		t.Fatal("sessions must be isolated")
	}
	s.Session = "$1"
	s.ServerStart = "start2"
	if workspaceID(s) == id {
		t.Fatal("server restart must not reuse old workspace")
	}
}
