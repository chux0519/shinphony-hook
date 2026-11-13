package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const origin = "https://notify.potafree.net"
const networkDeadline = 3 * time.Second

var errUnsafe = errors.New("unsafe_path_or_permissions")
var errConfig = errors.New("invalid_configuration")

type relay struct {
	origin string
	client *http.Client
}

func newRelay() relay {
	return relay{origin, &http.Client{Timeout: networkDeadline, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("redirect_refused") }}}
}
func lanePrefix(lane string) (string, error) {
	switch lane {
	case "sandbox":
		return "", nil
	case "testflight", "production":
		return "/" + lane, nil
	}
	return "", errConfig
}

// No endpoint override exposed to users: credentials only go to our fixed origin.
// Test code injects a local httptest transport. Never return server bodies/errors.
func (r relay) post(ctx context.Context, lane, path, token string, body, out any) error {
	prefix, err := lanePrefix(lane)
	if err != nil {
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return errConfig
	}
	req, err := http.NewRequestWithContext(ctx, "POST", r.origin+prefix+path, bytes.NewReader(data))
	if err != nil {
		return errConfig
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := r.client.Do(req)
	if err != nil {
		return errors.New("network_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 && !(path == "/v1/events" && response.StatusCode == 202) {
		return fmt.Errorf("relay_http_%d", response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, 8193))
	if err != nil || len(data) > 8192 {
		return errors.New("invalid_relay_response")
	}
	if json.Unmarshal(data, out) != nil {
		return errors.New("invalid_relay_response")
	}
	return nil
}

type event struct {
	ID     string `json:"eventId"`
	Status string `json:"status"`
}

func (r relay) send(ctx context.Context, c credential, e event) error {
	if !identifier.MatchString(e.ID) || !validStatus(e.Status) || !c.valid() {
		return errConfig
	}
	var reply struct {
		Accepted bool `json:"accepted"`
	}
	if err := r.post(ctx, c.Lane, "/v1/events", c.Token, e, &reply); err != nil {
		return err
	}
	if !reply.Accepted {
		return errors.New("event_not_accepted")
	}
	return nil
}
func validStatus(s string) bool { return s == "completed" || s == "failed" || s == "attention" }
