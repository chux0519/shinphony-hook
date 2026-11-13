package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func e2eCredentialBody(t *testing.T, liveLines bool) []byte {
	t.Helper()
	phone := vectorKey(t, "phone")
	credential := map[string]any{
		"schema": 1, "lane": "sandbox", "hostId": "host", "hostToken": strings.Repeat("a", 43),
		"e2e": map[string]any{"v": 1, "pub": b64(phone.PublicKey().Bytes())},
	}
	if liveLines {
		credential["liveActivityLines"] = true
	}
	raw, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func e2eDetails(t *testing.T) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(eventDetails{Category: "approval_required", Agent: "claude", Session: strings.Repeat("c", 32),
		Title: "Allow Bash?", Body: "npm test", Project: "hook", Visibility: "banner"})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func e2eContext() taskContext {
	return taskContext{Version: 1, Agent: "claude", Thread: "t1", Title: "hook", Multiplexer: "tmux",
		Session: "shinphony", Window: "0", Route: "event", Binary: strings.Repeat("b", 64), Preview: "npm test\n61 passing"}
}

// A private pairing sends the envelope and nothing readable. The phone opens it
// with the key it kept (the pairing's own credential is the only copy here).
func TestDeliverySealsPrivateNotifications(t *testing.T) {
	dir := privateTemp(t)
	os.WriteFile(filepath.Join(dir, "phone.json"), e2eCredentialBody(t, false), 0600)
	var got map[string]any
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		json.NewDecoder(r.Body).Decode(&got)
		return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(`{"accepted":true}`))}, nil
	})}
	call := context.WithValue(context.Background(), agentDetailsKey{}, e2eDetails(t))
	call = context.WithValue(call, taskContextKey{}, e2eContext())
	if r := deliver(dir, client)(call, Event{"phone", "event", "attention"}); r.Code != "accepted" {
		t.Fatal(r)
	}
	for _, key := range []string{"title", "body", "project", "agent", "session", "visibility", "context"} {
		if _, ok := got[key]; ok {
			t.Fatalf("%s sent in the clear: %v", key, got)
		}
	}
	if got["category"] != "approval_required" || got["eventId"] != "event" || got["status"] != "attention" {
		t.Fatal(got)
	}
	if got["hostRef"] != e2eHostRef("phone") || got["silent"] != false {
		t.Fatal(got)
	}
	raw, err := json.Marshal(got["e2e"])
	if err != nil || len(raw) > e2eMaxEnvelope {
		t.Fatal(len(raw), err)
	}
	var envelope e2eEnvelope
	if err = json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	opened, err := e2eOpen(vectorKey(t, "phone"), envelope, e2eHostRef("phone"))
	if err != nil {
		t.Fatal(err)
	}
	var plain e2ePlaintext
	if err = json.Unmarshal(opened, &plain); err != nil {
		t.Fatal(err)
	}
	if plain.Title != "Allow Bash?" || plain.Body != "npm test" || plain.Project != "hook" ||
		strings.Join(plain.Lines, "|") != "npm test|61 passing" || plain.Visibility != "banner" {
		t.Fatalf("%+v", plain)
	}
}

// Opting in to plaintext Live Activity lines sends today's title, body and
// terminal preview in the clear (the relay renders the Live Activity from them)
// while the alert itself stays sealed.
func TestDeliveryLiveActivityLinesAreOptIn(t *testing.T) {
	dir := privateTemp(t)
	os.WriteFile(filepath.Join(dir, "phone.json"), e2eCredentialBody(t, true), 0600)
	var got map[string]any
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		json.NewDecoder(r.Body).Decode(&got)
		return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(`{"accepted":true}`))}, nil
	})}
	call := context.WithValue(context.Background(), agentDetailsKey{}, e2eDetails(t))
	call = context.WithValue(call, taskContextKey{}, e2eContext())
	if r := deliver(dir, client)(call, Event{"phone", "event", "attention"}); r.Code != "accepted" {
		t.Fatal(r)
	}
	if got["liveLines"] != true || got["title"] != "Allow Bash?" || got["body"] != "npm test" ||
		got["project"] != "hook" || got["agent"] != "claude" || got["session"] != strings.Repeat("c", 32) {
		t.Fatal(got)
	}
	context, ok := got["context"].(map[string]any)
	if !ok || context["preview"] != "npm test\n61 passing" {
		t.Fatal(got["context"])
	}
	// The alert is still the envelope; `silent` is the routing bit.
	if _, ok := got["e2e"]; !ok {
		t.Fatal("envelope missing")
	}
	if _, ok := got["visibility"]; ok {
		t.Fatal("visibility should travel as silent")
	}
}

func TestDeliverySilentPrivateEvent(t *testing.T) {
	dir := privateTemp(t)
	os.WriteFile(filepath.Join(dir, "phone.json"), e2eCredentialBody(t, false), 0600)
	var got map[string]any
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		json.NewDecoder(r.Body).Decode(&got)
		return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader(`{"accepted":true}`))}, nil
	})}
	details := json.RawMessage(`{"category":"task_started","visibility":"silent"}`)
	if r := deliver(dir, client)(context.WithValue(context.Background(), agentDetailsKey{}, details), Event{"phone", "e1", "completed"}); r.Code != "accepted" {
		t.Fatal(r)
	}
	if got["silent"] != true {
		t.Fatal(got)
	}
}

// A relay without e2e support must never receive the plaintext instead.
func TestDeliveryNeverFallsBackToPlaintext(t *testing.T) {
	dir := privateTemp(t)
	os.WriteFile(filepath.Join(dir, "phone.json"), e2eCredentialBody(t, false), 0600)
	var requests int
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if _, leaked := body["title"]; leaked {
			t.Error("plaintext fallback")
		}
		return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{"error":"invalid_fields"}`))}, nil
	})}
	r := deliver(dir, client)(context.WithValue(context.Background(), agentDetailsKey{}, e2eDetails(t)), Event{"phone", "e1", "completed"})
	if r.Code != "relay_v1_e2e_unsupported" || r.Retry || requests != 1 {
		t.Fatal(r, requests)
	}
}

// A malformed key in a credential stops delivery instead of degrading it.
func TestDeliveryRejectsMalformedE2EKey(t *testing.T) {
	dir := privateTemp(t)
	os.WriteFile(filepath.Join(dir, "phone.json"), []byte(`{"schema":1,"lane":"sandbox","hostId":"host","hostToken":"`+
		strings.Repeat("a", 43)+`","e2e":{"v":1,"pub":"`+strings.Repeat("A", 42)+`"}}`), 0600)
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		t.Error("network used")
		return nil, io.EOF
	})}
	if r := deliver(dir, client)(context.Background(), Event{"phone", "e1", "completed"}); r.Code != "invalid_credential" {
		t.Fatal(r)
	}
}
