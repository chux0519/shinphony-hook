package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type presence struct {
	Profile string `json:"profile"`
	TTY     string `json:"tty"`
	Active  bool   `json:"active"`
}

func (q *queue) registerPresence(mux *http.ServeMux) {
	q.registerHcPresence(mux)
	mux.HandleFunc("POST /v1/presence", func(w http.ResponseWriter, r *http.Request) {
		var p presence
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
		d.DisallowUnknownFields()
		if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || !identifier.MatchString(p.Profile) || !regexp.MustCompile(`^/dev/[A-Za-z0-9/_-]{1,100}$`).MatchString(p.TTY) {
			http.Error(w, "invalid_presence", 400)
			return
		}
		var err error
		if p.Active {
			_, err = q.db.Exec("INSERT INTO task_presence VALUES(?,?,?) ON CONFLICT(profile) DO UPDATE SET tty=excluded.tty,expires=excluded.expires", p.Profile, p.TTY, time.Now().Unix()+20)
			if err == nil {
				q.rememberRecent(r.Context(), p.Profile, p.TTY)
			}
		} else {
			_, err = q.db.Exec("DELETE FROM task_presence WHERE profile=? AND tty=?", p.Profile, p.TTY)
		}
		if err != nil {
			http.Error(w, "storage_unavailable", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "expiresIn": 20})
	})
}
func (q *queue) activelyViewing(ctx context.Context, profile string, c *localSnapshot) bool {
	if c.Multiplexer == "hc" {
		var target string
		return q.db.QueryRow("SELECT target FROM hc_presence WHERE profile=? AND expires>?", profile, time.Now().Unix()).Scan(&target) == nil && target == snapshotRouteKey(c)
	}
	var tty string
	if q.db.QueryRow("SELECT tty FROM task_presence WHERE profile=? AND expires>?", profile, time.Now().Unix()).Scan(&tty) != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	output, err := tmuxOutput(ctx, "-S", c.Socket, "list-clients", "-F", "#{client_tty}\t#{pane_id}")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(output, "\n") {
		if line == tty+"\t"+c.PaneID {
			return true
		}
	}
	return false
}
