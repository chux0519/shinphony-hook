package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRecentProfileIsolationAndExpiry(t *testing.T) {
	q := testQueue(t)
	q.db.Exec("INSERT INTO recent_sessions VALUES(?,?,?)", "phone1", `{"pane":"%2"}`, time.Now().Unix())
	mux := http.NewServeMux()
	q.registerRecent(mux)
	for _, tc := range []struct {
		profile string
		code    int
	}{{"phone1", 200}, {"phone2", 404}, {"bad!", 400}} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/recent/"+tc.profile, nil))
		if w.Code != tc.code {
			t.Fatalf("%s: %d", tc.profile, w.Code)
		}
	}
	q.db.Exec("UPDATE recent_sessions SET updated=0")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/recent/phone1", nil))
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestRecentRealTmux(t *testing.T) {
	if os.Getenv("SHINPHONY_TEST_RECENT") != "1" {
		t.Skip("opt-in disposable tmux fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	socket := filepath.Join(t.TempDir(), "tmux")
	if _, err := tmuxOutput(ctx, "-S", socket, "-f", "/dev/null", "new-session", "-d", "-s", "recent-fixture"); err != nil {
		t.Fatal(err)
	}
	defer tmuxOutput(context.Background(), "-S", socket, "kill-server")
	raw, err := tmuxOutput(ctx, "-S", socket, "display-message", "-p", "-t", "recent-fixture", "#{pid}\t#{session_id}\t#{window_id}\t#{pane_id}\t#{pane_pid}")
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Split(strings.TrimSpace(raw), "\t")
	if len(f) != 5 {
		t.Fatal(raw)
	}
	s := &recentSession{Socket: socket, ServerPID: f[0], Session: f[1], Window: f[2], Pane: f[3], PanePID: f[4]}
	pid, _ := strconv.Atoi(s.ServerPID)
	s.ServerStart = processStart(ctx, pid)
	pid, _ = strconv.Atoi(s.PanePID)
	s.PaneStart = processStart(ctx, pid)
	if !validRecent(ctx, s) {
		t.Fatal("live target rejected")
	}
	s.ServerStart = "stale"
	if validRecent(ctx, s) {
		t.Fatal("recycled server accepted")
	}
	s.ServerStart = processStart(ctx, func() int { p, _ := strconv.Atoi(s.ServerPID); return p }())
	tmuxOutput(ctx, "-S", socket, "kill-session", "-t", s.Session)
	if validRecent(ctx, s) {
		t.Fatal("deleted session accepted")
	}
}

func TestParseRecent(t *testing.T) {
	good := "/dev/ttys001\t/tmp/tmux-501/default\t123\t$0\t@1\t%2\t456"
	got := parseRecent(good, "/dev/ttys001")
	if got == nil || got.Session != "$0" || got.Pane != "%2" {
		t.Fatal(got)
	}
	for _, raw := range []string{good + "\n" + good, "/dev/ttys001\t/tmp/s\t123\t$(evil)\t@1\t%2\t456", "junk"} {
		if parseRecent(raw, "/dev/ttys001") != nil {
			t.Fatalf("accepted ambiguous/invalid %q", raw)
		}
	}
	if parseRecent(good, "/dev/other") != nil {
		t.Fatal("selected another client")
	}
}
