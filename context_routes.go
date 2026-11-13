package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

func (q *queue) registerContexts(mux *http.ServeMux) {
	q.registerRecent(mux)
	q.registerWorkspaces(mux)
	mux.HandleFunc("POST /v1/focus-event", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Event string `json:"event"`
			TTY   string `json:"tty"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input) != nil || !identifier.MatchString(input.Event) || !strings.HasPrefix(input.TTY, "/dev/") || strings.ContainsAny(input.TTY, "\x00\r\n\t") {
			http.Error(w, "invalid_request", 400)
			return
		}
		c := q.contextForEvent(input.Event)
		if c == nil {
			http.Error(w, "target_expired_or_replaced", 404)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if c.Multiplexer == "hc" {
			// hc selection never changes another viewer's desktop focus.
			json.NewEncoder(w).Encode(map[string]bool{"focused": false})
			return
		}
		raw, err := tmuxOutput(ctx, "-S", c.Socket, "list-clients", "-F", "#{client_tty}\t#{socket_path}\t#{pid}\t#{session_id}\t#{window_id}\t#{pane_id}\t#{pane_pid}")
		client := parseRecent(raw, input.TTY)
		if err != nil || !sameContextSession(client, c) {
			json.NewEncoder(w).Encode(map[string]bool{"focused": false})
			return
		}
		if err = selectContext(ctx, c); err != nil {
			http.Error(w, "target_exited_or_replaced", 409)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"focused": true})
	})
	mux.HandleFunc("GET /v1/context/{event}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("event")
		if !identifier.MatchString(id) {
			http.Error(w, "invalid_event", 400)
			return
		}
		c := q.contextForEvent(id)
		if c == nil {
			http.Error(w, "target_expired_or_replaced", 404)
			return
		}
		json.NewEncoder(w).Encode(c)
	})
}

func fetchSnapshot(dir, id string) (*localSnapshot, error) {
	if !identifier.MatchString(id) {
		return nil, errors.New("invalid_event")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost/v1/context/"+id, nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, errors.New("daemon_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("target_expired_or_replaced")
	}
	var c localSnapshot
	if json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&c) != nil {
		return nil, errors.New("invalid_context")
	}
	return &c, nil
}
func attachContext(dir, id string) error {
	c, err := fetchSnapshot(dir, id)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if c.Multiplexer == "hc" {
		return attachHcContext(ctx, c)
	}
	if err = selectContext(ctx, c); err != nil {
		return err
	}
	return execAttach(tmuxExecutable(), []string{"-u", "-S", c.Socket, "attach-session", "-t", c.SessionID})
}

func sameContextSession(client *recentSession, c *localSnapshot) bool {
	return client != nil && c.Multiplexer == "tmux" && client.Socket == c.Socket && client.ServerPID == c.ServerPID && client.Session == c.SessionID
}

func selectContext(ctx context.Context, c *localSnapshot) error {
	if c.Multiplexer == "hc" {
		return validateHcContext(ctx, c)
	}
	if c.Multiplexer != "tmux" || !filepath.IsAbs(c.Socket) {
		return errors.New("unsupported_target")
	}
	raw, err := tmuxOutput(ctx, "-S", c.Socket, "display-message", "-p", "-t", c.PaneID, "#{pid}\t#{session_id}\t#{window_id}\t#{pane_id}\t#{pane_pid}")
	expected := strings.Join([]string{c.ServerPID, c.SessionID, c.WindowID, c.PaneID, c.PanePID}, "\t")
	if err != nil || strings.TrimSpace(raw) != expected || processStart(ctx, c.AgentPID) != c.AgentStart || !processUnderPane(ctx, c.AgentPID, c.PanePID) {
		return errors.New("target_exited_or_replaced")
	}
	// Never create a session or run codex resume from push-controlled strings.
	// select-pane uses stable numeric IDs. Other clients sharing this session may
	// see the pane selection too; no detach-client or kill-session is performed.
	if _, err = tmuxOutput(ctx, "-S", c.Socket, "select-pane", "-t", c.PaneID); err != nil {
		return errors.New("target_unavailable")
	}
	if _, err = tmuxOutput(ctx, "-S", c.Socket, "select-window", "-t", c.WindowID); err != nil {
		return errors.New("target_unavailable")
	}
	return nil
}
