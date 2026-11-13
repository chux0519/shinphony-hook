//go:build !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in only: the driver creates the private server, process ancestry and
// state. This never consults the user's ordinary tmux server or credentials.
func TestTaskIntentTmuxPresenceLive(t *testing.T) {
	state := os.Getenv("SHINPHONY_INTENT_FIX_STATE")
	if state == "" {
		t.Skip("requires isolated task-intent tmux driver")
	}
	if !strings.HasPrefix(filepath.Base(filepath.Dir(state)), "sp-hc-intent-") || privatePath(state, true) != nil {
		t.Fatal("dedicated private fixture required")
	}
	q, err := openQueue(filepath.Join(state, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.db.Close()
	c := q.contextForEvent(os.Getenv("SHINPHONY_INTENT_FIX_EVENT"))
	if c == nil || c.Multiplexer != "tmux" || c.PaneID != os.Getenv("SHINPHONY_INTENT_FIX_PANE") {
		t.Fatal("wrong real context")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, state) }}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	lease := func(active bool) {
		body, _ := json.Marshal(presence{Profile: "phone", TTY: os.Getenv("SHINPHONY_INTENT_FIX_TTY"), Active: active})
		resp, e := client.Post("http://local/v1/presence", "application/json", bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatal("lease rejected", resp.StatusCode)
		}
	}
	lease(true)
	defer lease(false)
	if !q.activelyViewing(ctx, "phone", c) {
		t.Fatal("real pane lease did not suppress")
	}
	lease(false)
	if q.activelyViewing(ctx, "phone", c) {
		t.Fatal("cleared lease still suppressed")
	}
	t.Log("real tmux client lease suppresses only while active")
}
