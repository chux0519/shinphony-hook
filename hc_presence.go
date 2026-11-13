package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// The foreground client renews an explicit target lease; an attached SSH
// connection alone is never evidence that the phone is still watching it.
// Route is a locally resolved event, not client-supplied hc socket/PID data.
func (q *queue) registerHcPresence(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/hc-presence", func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Profile string              `json:"profile"`
			Event   string              `json:"event"`
			Target  *hcPresenceIdentity `json:"target,omitempty"`
			Active  bool                `json:"active"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
		d.DisallowUnknownFields()
		if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || !identifier.MatchString(p.Profile) || ((p.Target == nil && !identifier.MatchString(p.Event)) || (p.Target != nil && (p.Event != "" || !p.Target.valid()))) {
			http.Error(w, "invalid_presence", 400)
			return
		}
		var c *localSnapshot
		if p.Target != nil {
			c = q.hcContextForIdentity(*p.Target)
		} else {
			c = q.contextForEvent(p.Event)
		}
		if c == nil || c.Multiplexer != "hc" {
			http.Error(w, "target_expired_or_replaced", 404)
			return
		}
		key := snapshotRouteKey(c)
		if p.Active {
			ctx, cancel := context.WithTimeout(r.Context(), 1200*time.Millisecond)
			defer cancel()
			if validateHcContext(ctx, c) != nil {
				http.Error(w, "target_exited_or_replaced", 409)
				return
			}
			if _, e := q.db.Exec("INSERT INTO hc_presence VALUES(?,?,?) ON CONFLICT(profile) DO UPDATE SET target=excluded.target,expires=excluded.expires", p.Profile, key, time.Now().Unix()+20); e != nil {
				http.Error(w, "storage_unavailable", 503)
				return
			}
		} else {
			// A late inactive message for an old target cannot clear the new lease.
			if _, e := q.db.Exec("DELETE FROM hc_presence WHERE profile=? AND target=?", p.Profile, key); e != nil {
				http.Error(w, "storage_unavailable", 503)
				return
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "expiresIn": 20})
	})
}

// Identity-only renewals let a foreground picker-attached tab suppress its
// task before the first notification tap. Resolve only from verified Hook
// snapshots, never from a caller-supplied socket or an arbitrary core scan.
// The pid and core id are caller diagnostics: like the route key, the terminal
// is the address and created_ms, so a kept-program or core restart still owns
// its lease. A recreated terminal has a new created_ms and matches nothing.
type hcPresenceIdentity struct {
	CoreID    string `json:"coreId"`
	Address   string `json:"address"`
	CreatedMS int64  `json:"createdMs"`
	PID       int    `json:"pid"`
}

func (t hcPresenceIdentity) valid() bool {
	return identifier.MatchString(t.CoreID) && hcAddressRE.MatchString(t.Address) && t.CreatedMS > 0 && t.PID > 1
}
func (q *queue) hcContextForIdentity(t hcPresenceIdentity) *localSnapshot {
	rows, e := q.db.Query("SELECT snapshot FROM task_contexts WHERE updated>? ORDER BY updated DESC LIMIT 128", time.Now().Unix()-86400)
	if e != nil {
		return nil
	}
	defer rows.Close()
	var found *localSnapshot
	for rows.Next() {
		var raw string
		var c localSnapshot
		if rows.Scan(&raw) != nil || json.Unmarshal([]byte(raw), &c) != nil || c.Hc == nil {
			continue
		}
		h := c.Hc
		if c.Multiplexer == "hc" && h.Address == t.Address && h.CreatedMS == t.CreatedMS {
			if found != nil {
				return nil
			}
			copy := c
			found = &copy
		}
	}
	return found
}
