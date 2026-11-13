package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"net.potafree/shinphony/hook/internal/notifier"
)

type setupRequest struct {
	ID      string `json:"jobId"`
	Agent   string `json:"agent"`
	Profile string `json:"profile"`
	Lane    string `json:"lane"`
	Host    string `json:"hostId"`
}
type setupResult struct {
	setupRequest
	State   string `json:"state"`
	Code    string `json:"code"`
	Updated int64  `json:"updated"`
}

func (j setupRequest) valid() bool {
	return identifier.MatchString(j.ID) && identifier.MatchString(j.Profile) && identifier.MatchString(j.Host) && (j.Agent == "auto" || j.Agent == "codex" || j.Agent == "claude" || j.Agent == "dsh") && (j.Lane == "sandbox" || j.Lane == "testflight" || j.Lane == "production")
}
func (q *queue) initJobs() error {
	// Do not silently replay a possibly applied config transaction after a crash.
	_, err := q.db.Exec("UPDATE setup_jobs SET state='interrupted',code='check_and_retry',updated=? WHERE state='running'", time.Now().Unix())
	return err
}
func (q *queue) job(id string) (setupResult, error) {
	var r setupResult
	err := q.db.QueryRow("SELECT id,agent,profile,lane,host,state,code,updated FROM setup_jobs WHERE id=?", id).Scan(&r.ID, &r.Agent, &r.Profile, &r.Lane, &r.Host, &r.State, &r.Code, &r.Updated)
	return r, err
}
func (q *queue) submit(j setupRequest) (setupResult, error) {
	if !j.valid() {
		return setupResult{}, errors.New("invalid_setup")
	}
	old, err := q.job(j.ID)
	if err == nil {
		if old.setupRequest != j {
			return old, errors.New("job_conflict")
		}
		return old, nil
	}
	if err != sql.ErrNoRows {
		return old, err
	}
	tx, err := q.db.Begin()
	if err != nil {
		return old, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM setup_jobs WHERE updated<? AND state IN ('succeeded','failed','interrupted')", time.Now().Unix()-7*86400); err != nil {
		return old, err
	}
	var count int
	if err = tx.QueryRow("SELECT count(*) FROM setup_jobs").Scan(&count); err != nil {
		return old, err
	}
	if count >= 100 {
		return old, errors.New("job_limit")
	}
	_, err = tx.Exec("INSERT INTO setup_jobs(id,agent,profile,lane,host,state,code,updated) VALUES(?,?,?,?,?,'queued','',?)", j.ID, j.Agent, j.Profile, j.Lane, j.Host, time.Now().Unix())
	if err != nil {
		return old, err
	}
	if err = tx.Commit(); err != nil {
		return old, err
	}
	return q.job(j.ID)
}
func (q *queue) setJob(id, state, code string) error {
	_, err := q.db.Exec("UPDATE setup_jobs SET state=?,code=?,updated=? WHERE id=?", state, code, time.Now().Unix(), id)
	return err
}

// setupNotice is a successful setup that still needs the user, e.g. reviewing
// new Codex hooks; it becomes the job's code instead of restart_agent_required.
type setupNotice string

func (n setupNotice) Error() string { return string(n) }

func (q *queue) processJob(execute func(setupRequest) error) (bool, error) {
	q.profileMu.Lock()
	defer q.profileMu.Unlock()
	var id string
	err := q.db.QueryRow("SELECT id FROM setup_jobs WHERE state='queued' ORDER BY updated LIMIT 1").Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	j, err := q.job(id)
	if err != nil {
		return false, err
	}
	if err = q.setJob(id, "running", ""); err != nil {
		return false, err
	}
	err = execute(j.setupRequest)
	var notice setupNotice
	if errors.As(err, &notice) {
		return true, q.setJob(id, "succeeded", string(notice))
	}
	if err != nil {
		code := err.Error()
		if !identifier.MatchString(code) {
			code = "setup_failed"
		}
		return true, q.setJob(id, "failed", code)
	}
	return true, q.setJob(id, "succeeded", "restart_agent_required")
}
func jobsWorker(ctx context.Context, q *queue, manager notifier.Manager, exe string) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		_, err := q.processJob(func(j setupRequest) error {
			paired, err := manager.Paired(j.Profile, j.Lane, j.Host)
			if err != nil {
				return err
			}
			if !paired {
				return errors.New("pairing_required")
			}
			if err = configureSetupAgents(manager, j.Agent, exe); err != nil {
				return err
			}
			// Installation status is queried by the App, not a task completion.
			return nil
		})
		if err != nil {
			return safeDBError(err)
		}
	}
}

// pairingSettings reads the optional update fields of the pairing input. An
// absent `e2e` leaves the stored key alone, `null` removes it (the pairing goes
// back to plaintext), and an object sets or rotates it. A malformed key is a
// clear error that never touches the stored pairing.
func pairingSettings(raw json.RawMessage, lines *bool) (notifier.PairingSettings, error) {
	s := notifier.PairingSettings{LiveActivityLines: lines}
	if len(raw) > 0 {
		if string(bytes.TrimSpace(raw)) == "null" {
			s.RemoveE2E = true
		} else {
			var key notifier.E2EKey
			if json.Unmarshal(raw, &key) != nil || key.V != 1 || !validE2EPublicKey(key.Pub) {
				return s, errors.New("invalid_e2e_key")
			}
			s.E2E = &key
		}
	}
	return s, nil
}

func registerSetup(mux *http.ServeMux, q *queue, manager notifier.Manager) {
	mux.HandleFunc("POST /v1/reset-profile", func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Profile string `json:"profile"`
			Lane    string `json:"lane"`
			Host    string `json:"hostId"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || !(setupRequest{"reset", "codex", p.Profile, p.Lane, p.Host}).valid() {
			http.Error(w, "invalid_pairing", 400)
			return
		}
		q.profileMu.Lock()
		defer q.profileMu.Unlock()
		// The App revokes at the relay first. Cancel durable work before removing
		// credentials, so an interrupted reset can safely be retried.
		if err := manager.ValidateReset(p.Profile, p.Lane, p.Host); err != nil {
			http.Error(w, "pairing_mismatch", 409)
			return
		}
		tx, err := q.db.Begin()
		if err != nil {
			http.Error(w, "storage_unavailable", 503)
			return
		}
		defer tx.Rollback()
		if _, err = tx.Exec("DELETE FROM outbox WHERE profile=?", p.Profile); err == nil {
			_, err = tx.Exec("UPDATE setup_jobs SET state='interrupted',code='pairing_reset',updated=? WHERE profile=? AND state IN ('queued','running')", time.Now().Unix(), p.Profile)
		}
		if err != nil || tx.Commit() != nil {
			http.Error(w, "storage_unavailable", 503)
			return
		}
		if err = manager.Reset(p.Profile); err != nil {
			http.Error(w, "pairing_recovery_failed", 409)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"reset": true})
	})
	mux.HandleFunc("POST /v1/pairing-status", func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Profile string `json:"profile"`
			Lane    string `json:"lane"`
			Host    string `json:"hostId"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid_pairing", 400)
			return
		}
		paired, err := manager.Paired(p.Profile, p.Lane, p.Host)
		if err != nil {
			http.Error(w, "pairing_needs_reconciliation", 409)
			return
		}
		out := map[string]any{"paired": paired, "e2eSupported": true}
		if paired {
			// The App shows the Live Activity choice per host; `private` tells it
			// this pairing carries a key. `e2eSupported` says this Hook accepts the
			// key on the pairing update path, so a legacy pairing can still gain
			// one without re-pairing.
			if lines, private, e := manager.LiveActivityLines(p.Profile); e == nil {
				out["liveActivityLines"], out["private"] = lines, private
			}
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/setup-latest/{profile}", func(w http.ResponseWriter, r *http.Request) {
		profile := r.PathValue("profile")
		if !identifier.MatchString(profile) {
			http.Error(w, "invalid_profile", 400)
			return
		}
		var id string
		err := q.db.QueryRow("SELECT id FROM setup_jobs WHERE profile=? ORDER BY updated DESC,rowid DESC LIMIT 1", profile).Scan(&id)
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(map[string]any{"state": "not_started"})
			return
		}
		if err != nil {
			http.Error(w, "storage_unavailable", 503)
			return
		}
		result, err := q.job(id)
		if err != nil {
			http.Error(w, "job_not_found", 404)
			return
		}
		json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("POST /v1/pair", func(w http.ResponseWriter, r *http.Request) {
		q.profileMu.Lock()
		defer q.profileMu.Unlock()
		var p struct {
			Profile string `json:"profile"`
			Lane    string `json:"lane"`
			Host    string `json:"hostId"`
			Code    string `json:"code"`
			// The pairing input may carry the phone's notification key and the
			// Live Activity choice; both are optional so an older App still pairs.
			// `e2e` is raw so that an absent key (leave it alone), `null` (remove
			// it) and an object (set or rotate it) stay distinguishable.
			E2E               json.RawMessage `json:"e2e,omitempty"`
			LiveActivityLines *bool           `json:"liveActivityLines,omitempty"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid_pairing", 400)
			return
		}
		// A malformed key is a clear error, never a silent fall back to plaintext.
		settings, err := pairingSettings(p.E2E, p.LiveActivityLines)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		lines := p.LiveActivityLines != nil && *p.LiveActivityLines
		paired, err := manager.Paired(p.Profile, p.Lane, p.Host)
		if err == nil && paired {
			// An existing pairing accepts the same fields as an update, without a
			// new code: set, rotate or remove the key, and change the Live Activity
			// choice. Host, lane and token never change here.
			if settings.Empty() {
				json.NewEncoder(w).Encode(map[string]any{"paired": true, "deliveryVerified": false})
				return
			}
			if err = manager.UpdatePairing(p.Profile, p.Lane, p.Host, settings); err != nil {
				code := err.Error()
				if !identifier.MatchString(code) {
					code = "pairing_update_failed"
				}
				http.Error(w, code, 409)
				return
			}
			updated := []string{}
			if settings.RemoveE2E || settings.E2E != nil {
				updated = append(updated, "e2e")
			}
			if settings.LiveActivityLines != nil {
				updated = append(updated, "liveActivityLines")
			}
			private, lines := false, false
			if value, keyed, e := manager.LiveActivityLines(p.Profile); e == nil {
				lines, private = value, keyed
			}
			json.NewEncoder(w).Encode(map[string]any{"paired": true, "updated": updated,
				"private": private, "liveActivityLines": lines})
			return
		}
		if err == nil {
			err = manager.PairE2E(p.Profile, p.Lane, p.Host, p.Code, settings.E2E, lines)
		}
		if err != nil {
			code := err.Error()
			if !identifier.MatchString(code) {
				code = "pairing_failed"
			}
			http.Error(w, code, 409)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"paired": true, "deliveryVerified": false})
	})
	mux.HandleFunc("POST /v1/setup", func(w http.ResponseWriter, r *http.Request) {
		q.profileMu.Lock()
		defer q.profileMu.Unlock()
		var j setupRequest
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || !j.valid() {
			http.Error(w, "invalid_setup", 400)
			return
		}
		paired, err := manager.Paired(j.Profile, j.Lane, j.Host)
		if err != nil || !paired {
			http.Error(w, "pairing_required", 409)
			return
		}
		result, err := q.submit(j)
		if err != nil {
			http.Error(w, "setup_rejected", 409)
			return
		}
		json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("GET /v1/setup/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !identifier.MatchString(id) {
			http.Error(w, "invalid_id", 400)
			return
		}
		result, err := q.job(id)
		if err != nil {
			http.Error(w, "job_not_found", 404)
			return
		}
		json.NewEncoder(w).Encode(result)
	})
}
