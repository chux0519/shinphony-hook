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
type agentDetailsKey struct{}
type credential struct {
	Schema int    `json:"schema"`
	Lane   string `json:"lane"`
	Host   string `json:"hostId"`
	Token  string `json:"hostToken"`
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
		prefix := ""
		switch c.Lane {
		case "sandbox":
		case "production", "testflight":
			prefix = "/" + c.Lane
		default:
			return result{Code: "invalid_credential"}
		}
		fields := map[string]any{"eventId": e.ID, "status": e.Status}
		if c := ctx.Value(taskContextKey{}); c != nil {
			fields["context"] = c
		}
		// v2 agent-event details are top-level fields of the relay request.
		details, hasDetails := ctx.Value(agentDetailsKey{}).(json.RawMessage)
		if hasDetails && json.Unmarshal(details, &fields) != nil {
			return result{Code: "invalid_event"}
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
