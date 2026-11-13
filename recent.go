package main

// Recent destinations are local to a paired phone profile, independent of task
// events. Never infer a destination from an agent title or most-active session.
import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type recentSession struct {
	Socket      string `json:"socket"`
	ServerPID   string `json:"serverPid"`
	ServerStart string `json:"serverStart"`
	Session     string `json:"session"`
	Window      string `json:"window"`
	Pane        string `json:"pane"`
	PanePID     string `json:"panePid"`
	PaneStart   string `json:"paneStart"`
}

func parseRecent(raw, tty string) *recentSession {
	var found *recentSession
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 7 || f[0] != tty {
			continue
		}
		if found != nil {
			return nil
		}
		if !filepath.IsAbs(f[1]) || !regexp.MustCompile(`^[0-9]+$`).MatchString(f[2]) ||
			!regexp.MustCompile(`^\$[0-9]+$`).MatchString(f[3]) ||
			!regexp.MustCompile(`^@[0-9]+$`).MatchString(f[4]) ||
			!regexp.MustCompile(`^%[0-9]+$`).MatchString(f[5]) ||
			!regexp.MustCompile(`^[0-9]+$`).MatchString(f[6]) {
			return nil
		}
		found = &recentSession{Socket: f[1], ServerPID: f[2], Session: f[3], Window: f[4], Pane: f[5], PanePID: f[6]}
	}
	return found
}

func (q *queue) rememberRecent(parent context.Context, profile, tty string) {
	ctx, cancel := context.WithTimeout(parent, 600*time.Millisecond)
	defer cancel()
	raw, err := tmuxOutput(ctx, "list-clients", "-F", "#{client_tty}\t#{socket_path}\t#{pid}\t#{session_id}\t#{window_id}\t#{pane_id}\t#{pane_pid}")
	if err != nil {
		return
	}
	s := parseRecent(raw, tty)
	if s == nil {
		return
	}
	pid, _ := strconv.Atoi(s.ServerPID)
	s.ServerStart = processStart(ctx, pid)
	pid, _ = strconv.Atoi(s.PanePID)
	s.PaneStart = processStart(ctx, pid)
	if s.ServerStart == "" || s.PaneStart == "" {
		return
	}
	data, _ := json.Marshal(s)
	q.db.Exec("INSERT INTO recent_sessions VALUES(?,?,?) ON CONFLICT(profile) DO UPDATE SET snapshot=excluded.snapshot,updated=excluded.updated", profile, string(data), time.Now().Unix())
	q.db.Exec("DELETE FROM recent_sessions WHERE profile NOT IN (SELECT profile FROM recent_sessions ORDER BY updated DESC LIMIT 128)")
}

func (q *queue) registerRecent(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/recent/{profile}", func(w http.ResponseWriter, r *http.Request) {
		p := r.PathValue("profile")
		if !identifier.MatchString(p) {
			http.Error(w, "invalid_profile", 400)
			return
		}
		var raw string
		if q.db.QueryRow("SELECT snapshot FROM recent_sessions WHERE profile=? AND updated>?", p, time.Now().Add(-30*24*time.Hour).Unix()).Scan(&raw) != nil {
			http.Error(w, "no_recent_session", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, raw)
	})
}

func attachRecent(dir, profile string) error {
	if !identifier.MatchString(profile) {
		return errors.New("invalid_profile")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost/v1/recent/"+profile, nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return errors.New("daemon_unavailable")
	}
	defer resp.Body.Close()
	var s recentSession
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&s) != nil {
		return errors.New("no_recent_session")
	}
	if !validRecent(ctx, &s) {
		return errors.New("recent_session_expired")
	}
	if _, err = tmuxOutput(ctx, "-S", s.Socket, "select-window", "-t", s.Session+":"+s.Window); err != nil {
		return err
	}
	if _, err = tmuxOutput(ctx, "-S", s.Socket, "select-pane", "-t", s.Session+":"+s.Window+"."+s.Pane); err != nil {
		return err
	}
	return execAttach(tmuxExecutable(), []string{"-u", "-S", s.Socket, "attach-session", "-t", s.Session})
}

func validRecent(ctx context.Context, s *recentSession) bool {
	raw, err := tmuxOutput(ctx, "-S", s.Socket, "display-message", "-p", "-t", s.Session+":"+s.Window+"."+s.Pane, "#{pid}\t#{session_id}\t#{window_id}\t#{pane_id}\t#{pane_pid}")
	pid, _ := strconv.Atoi(s.ServerPID)
	panePID, _ := strconv.Atoi(s.PanePID)
	return err == nil && strings.TrimSpace(raw) == strings.Join([]string{s.ServerPID, s.Session, s.Window, s.Pane, s.PanePID}, "\t") && s.ServerStart != "" && s.PaneStart != "" && processStart(ctx, pid) == s.ServerStart && processStart(ctx, panePID) == s.PaneStart
}
