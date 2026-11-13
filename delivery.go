package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type result struct {
	Code  string
	Retry bool
	After time.Duration
}
type sender func(context.Context, Event) result

// taskContextOf reads the projection any caller may have attached.
func taskContextOf(ctx context.Context) (taskContext, bool) {
	switch value := ctx.Value(taskContextKey{}).(type) {
	case taskContext:
		return value, true
	case *taskContext:
		if value != nil {
			return *value, true
		}
	case *localSnapshot:
		if value != nil {
			return value.taskContext, true
		}
	}
	return taskContext{}, false
}

type agentDetailsKey struct{}
type credential struct {
	Schema int    `json:"schema"`
	Lane   string `json:"lane"`
	Host   string `json:"hostId"`
	Token  string `json:"hostToken"`
	// Private notifications: the phone's key. `liveActivityLines` asks for the
	// Live Activity to keep today's plaintext title and terminal lines; off (the
	// default, and the only mode an older App can mean) keeps it to state, time
	// and hostRef.
	E2E               *e2eKey `json:"e2e,omitempty"`
	LiveActivityLines bool    `json:"liveActivityLines,omitempty"`
}

func deliver(dir string, client *http.Client) sender {
	var send sender
	send = func(ctx context.Context, e Event) result {
		if !e.valid() {
			return result{Code: "invalid_event"}
		}
		if err := privatePath(dir, true); err != nil {
			return result{Code: "credential_unavailable"}
		}
		path := filepath.Join(dir, e.Profile+".json")
		if err := privatePath(path, false); err != nil {
			return result{Code: "credential_unavailable"}
		}
		f, err := os.Open(path)
		if err != nil {
			return result{Code: "credential_unavailable"}
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, 8193))
		if err != nil || len(raw) > 8192 {
			return result{Code: "invalid_credential"}
		}
		var c credential
		if json.Unmarshal(raw, &c) != nil || c.Schema != 1 || !identifier.MatchString(c.Host) || len(c.Token) != 43 || !identifier.MatchString(c.Token) {
			return result{Code: "invalid_credential"}
		}
		var phonePub []byte
		if c.E2E != nil {
			// A malformed key never falls back to plaintext: it stops delivery.
			if c.E2E.V != 1 || !validE2EPublicKey(c.E2E.Pub) {
				return result{Code: "invalid_credential"}
			}
			phonePub, _ = e2ePublicKey(c.E2E.Pub)
		}
		prefix := ""
		switch c.Lane {
		case "sandbox":
		case "production", "testflight":
			prefix = "/" + c.Lane
		default:
			return result{Code: "invalid_credential"}
		}
		fields := map[string]any{"eventId": e.ID, "status": e.Status}
		snapshot, hasContext := taskContextOf(ctx)
		// v2 agent-event details are top-level fields of the relay request.
		details, hasDetails := ctx.Value(agentDetailsKey{}).(json.RawMessage)
		if c.E2E != nil {
			// Private: the text is sealed to the phone and only the routing the
			// relay needs stays readable.
			var d eventDetails
			if hasDetails && json.Unmarshal(details, &d) != nil {
				return result{Code: "invalid_event"}
			}
			var context *taskContext
			if hasContext {
				context = &snapshot
			}
			private, err := e2eFields(randomReader, phonePub, e2eHostRef(e.Profile), &d, context)
			if err != nil {
				if identifier.MatchString(err.Error()) {
					return result{Code: err.Error()}
				}
				return result{Code: "e2e_failed"}
			}
			for key, value := range private {
				fields[key] = value
			}
			if c.LiveActivityLines {
				// Opted in: today's title and terminal lines travel in the clear for
				// the Live Activity. The alert is still the sealed envelope above.
				for _, field := range []struct{ name, value string }{
					{"agent", d.Agent}, {"session", d.Session}, {"title", d.Title}, {"body", d.Body}, {"project", d.Project},
				} {
					if field.value != "" {
						fields[field.name] = field.value
					}
				}
				if hasContext {
					fields["context"] = context
				}
				fields["liveLines"] = true
			}
			delete(fields, "visibility")
		} else {
			if hasContext {
				fields["context"] = snapshot
			}
			if hasDetails && json.Unmarshal(details, &fields) != nil {
				return result{Code: "invalid_event"}
			}
		}
		fields["eventId"], fields["status"] = e.ID, e.Status
		body, _ := json.Marshal(fields)
		req, _ := http.NewRequestWithContext(ctx, "POST", "https://notify.potafree.net"+prefix+"/v1/events", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.Token)
		resp, err := client.Do(req)
		if err != nil {
			return result{Code: "network_unavailable", Retry: true}
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
		if resp.StatusCode == 200 || resp.StatusCode == 202 {
			var r struct {
				Accepted bool `json:"accepted"`
			}
			if err == nil && len(data) <= 8192 && json.Unmarshal(data, &r) == nil && r.Accepted {
				return result{Code: "accepted"}
			}
			return result{Code: "invalid_response", Retry: true}
		}
		if resp.StatusCode == 400 && c.E2E != nil {
			// A relay without e2e support. Never degrade a private event to the
			// plaintext path: the user chose encryption, so it is dropped instead.
			return result{Code: "relay_v1_e2e_unsupported"}
		}
		if resp.StatusCode == 400 && hasDetails {
			var r struct {
				Error string `json:"error"`
			}
			if json.Unmarshal(data, &r) == nil && r.Error == "invalid_fields" {
				// A relay without v2 support. A banner degrades to the old
				// event; a silent one is dropped, since v1 can only alert.
				if fields["visibility"] == "silent" {
					return result{Code: "relay_v1_silent_dropped"}
				}
				return send(context.WithValue(ctx, agentDetailsKey{}, nil), e)
			}
		}
		retry := resp.StatusCode == 408 || resp.StatusCode == 429 || resp.StatusCode >= 500
		after := time.Duration(0)
		header := strings.TrimSpace(resp.Header.Get("Retry-After"))
		if n, err := strconv.ParseInt(header, 10, 32); err == nil && n > 0 {
			after = time.Duration(n) * time.Second
		} else if t, err := http.ParseTime(header); err == nil {
			after = time.Until(t)
		}
		return result{Code: "http_" + strconv.Itoa(resp.StatusCode), Retry: retry, After: after}
	}
	return send
}
