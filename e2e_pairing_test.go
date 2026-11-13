package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"net.potafree/shinphony/hook/internal/notifier"
)

func pairingPost(t *testing.T, client *http.Client, body string) (int, string) {
	t.Helper()
	resp, err := client.Post("http://local/v1/pair", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(raw))
}

func pairingStatus(t *testing.T, client *http.Client, profile string) map[string]any {
	t.Helper()
	resp, err := client.Post("http://local/v1/pairing-status", "application/json",
		strings.NewReader(`{"profile":"`+profile+`","lane":"sandbox","hostId":"host"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var status map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

// storedCredential reads one pairing file as JSON.
func storedCredential(t *testing.T, creds, profile string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(creds, profile+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(creds, profile+".json")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("credential mode: %v %v", info, err)
	}
	var c map[string]any
	if err = json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// pairingDaemon runs the real daemon against a private directory with a fake
// relay, and returns a client for the local socket.
func pairingDaemon(t *testing.T) (*http.Client, string, notifier.Manager) {
	t.Helper()
	home := privateTemp(t)
	t.Setenv("HOME", home)
	dir := filepath.Join(home, "state")
	creds := filepath.Join(home, "credentials")
	os.Mkdir(dir, 0700)
	manager := notifier.Manager{Directory: creds, Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"hostId":"host","hostToken":"` +
			strings.Repeat("a", 43) + `"}`)), Header: make(http.Header)}, nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, dir, func(context.Context, Event) result { return result{Code: "accepted"} }, creds)
	}()
	t.Cleanup(func() { cancel(); <-done })
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("http://local/v1/status")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return client, creds, manager
}

// The notification pairing input carries the phone's key and the Live Activity
// choice. A malformed key is a clear error, and an existing pairing accepts a
// later change of the choice over the same input (the App reaches the Hook over
// SSH and runs `pair` with that JSON).
func TestPairingAcceptsE2EKey(t *testing.T) {
	client, creds, manager := pairingDaemon(t)
	pub := b64(vectorKey(t, "phone").PublicKey().Bytes())
	// A pairing without a key is the legacy plain path, unchanged on disk.
	if err := manager.Pair("legacy", "sandbox", "host", strings.Repeat("b", 43)); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(creds, "legacy.json")); err != nil || strings.Contains(string(raw), "e2e") {
		t.Fatal(string(raw), err)
	}
	// A private pairing stores the key and the Live Activity choice.
	if err := manager.PairE2E("phone", "sandbox", "host", strings.Repeat("b", 43), &notifier.E2EKey{V: 1, Pub: pub}, true); err != nil {
		t.Fatal(err)
	}
	c := storedCredential(t, creds, "phone")
	if key, _ := c["e2e"].(map[string]any); key["v"] != float64(1) || key["pub"] != pub || c["liveActivityLines"] != true {
		t.Fatal(c)
	}
	// A key version nobody speaks is refused before any request.
	if err := manager.PairE2E("new", "sandbox", "host", strings.Repeat("b", 43), &notifier.E2EKey{V: 2, Pub: pub}, false); err == nil {
		t.Fatal("accepted a key version nobody speaks")
	}
	if _, err := os.Stat(filepath.Join(creds, "new.json")); !os.IsNotExist(err) {
		t.Fatal("a rejected key wrote a credential")
	}
	// The route rejects a malformed key with its own clear error, and spends
	// no pairing code doing it.
	for _, bad := range []string{
		`{"profile":"new","lane":"sandbox","hostId":"host","code":"` + strings.Repeat("b", 43) + `","e2e":{"v":1,"pub":"short"}}`,
		`{"profile":"new","lane":"sandbox","hostId":"host","code":"` + strings.Repeat("b", 43) + `","e2e":{"v":2,"pub":"` + pub + `"}}`,
		`{"profile":"new","lane":"sandbox","hostId":"host","code":"` + strings.Repeat("b", 43) + `","e2e":{}`,
		`{"profile":"new","lane":"sandbox","hostId":"host","code":"` + strings.Repeat("b", 43) + `","e2e":{"v":1,"pub":"` + pub + `"},"liveActivityLines":"yes"}`,
	} {
		if status, body := pairingPost(t, client, bad); status != 400 ||
			(!strings.Contains(body, "invalid_e2e_key") && !strings.Contains(body, "invalid_pairing")) {
			t.Fatalf("%d %s", status, body)
		}
	}
	if _, err := os.Stat(filepath.Join(creds, "new.json")); !os.IsNotExist(err) {
		t.Fatal("a rejected key wrote a credential")
	}
	if status := pairingStatus(t, client, "phone"); status["paired"] != true || status["private"] != true || status["liveActivityLines"] != true {
		t.Fatal(status)
	}
	// A legacy pairing on this Hook: no key yet, but the update path can add one.
	if status := pairingStatus(t, client, "legacy"); status["paired"] != true || status["private"] != false || status["e2eSupported"] != true {
		t.Fatal(status)
	}
	// The choice can change later over the same input, without a pairing code.
	// Nothing else about the pairing changes: the key stays.
	if status, body := pairingPost(t, client, `{"profile":"phone","lane":"sandbox","hostId":"host","liveActivityLines":false}`); status != 200 ||
		!strings.Contains(body, `"updated":["liveActivityLines"]`) || !strings.Contains(body, `"private":true`) {
		t.Fatal(status, body)
	}
	if status := pairingStatus(t, client, "phone"); status["liveActivityLines"] != false || status["private"] != true {
		t.Fatal(status)
	}
	updated := storedCredential(t, creds, "phone")
	if key, _ := updated["e2e"].(map[string]any); key["pub"] != pub || updated["hostToken"] != strings.Repeat("a", 43) {
		t.Fatal(updated)
	}
	// Another host never updates this pairing, and a missing profile is refused.
	if status, _ := pairingPost(t, client, `{"profile":"phone","lane":"sandbox","hostId":"other","liveActivityLines":true}`); status != 409 {
		t.Fatal(status)
	}
	if status := pairingStatus(t, client, "nobody"); status["paired"] != false || status["e2eSupported"] != true {
		t.Fatal(status)
	}
}

// Round 2: an existing pairing gains, rotates and drops the key through the
// same local call the App already makes over SSH (`shinphony-hook pair` with
// JSON on stdin, no pairing code).
func TestPairingUpdatesE2EKey(t *testing.T) {
	client, creds, manager := pairingDaemon(t)
	first := b64(vectorKey(t, "phone").PublicKey().Bytes())
	second := b64(vectorKey(t, "stranger").PublicKey().Bytes())
	if err := manager.Pair("phone", "sandbox", "host", strings.Repeat("b", 43)); err != nil {
		t.Fatal(err)
	}
	// A legacy pairing becomes private without re-pairing.
	if status, body := pairingPost(t, client, `{"profile":"phone","lane":"sandbox","hostId":"host","e2e":{"v":1,"pub":"`+first+`"}}`); status != 200 ||
		!strings.Contains(body, `"updated":["e2e"]`) || !strings.Contains(body, `"private":true`) {
		t.Fatal(status, body)
	}
	c := storedCredential(t, creds, "phone")
	if key, _ := c["e2e"].(map[string]any); key["pub"] != first || c["hostToken"] != strings.Repeat("a", 43) || c["hostId"] != "host" {
		t.Fatal(c)
	}
	// Rotating replaces the key; the rest of the pairing is untouched.
	if status, _ := pairingPost(t, client, `{"profile":"phone","lane":"sandbox","hostId":"host","e2e":{"v":1,"pub":"`+second+`"}}`); status != 200 {
		t.Fatal(status)
	}
	if c = storedCredential(t, creds, "phone"); c["e2e"].(map[string]any)["pub"] != second {
		t.Fatal(c)
	}
	// A malformed key changes nothing, not even the choice sent with it.
	if status, body := pairingPost(t, client, `{"profile":"phone","lane":"sandbox","hostId":"host","e2e":{"v":1,"pub":"short"},"liveActivityLines":true}`); status != 400 ||
		!strings.Contains(body, "invalid_e2e_key") {
		t.Fatal(status, body)
	}
	if c = storedCredential(t, creds, "phone"); c["e2e"].(map[string]any)["pub"] != second || c["liveActivityLines"] == true {
		t.Fatal(c)
	}
	// Both fields in one call, applied together.
	if status, body := pairingPost(t, client, `{"profile":"phone","lane":"sandbox","hostId":"host","e2e":{"v":1,"pub":"`+first+`"},"liveActivityLines":true}`); status != 200 ||
		!strings.Contains(body, `"updated":["e2e","liveActivityLines"]`) {
		t.Fatal(status, body)
	}
	c = storedCredential(t, creds, "phone")
	if c["e2e"].(map[string]any)["pub"] != first || c["liveActivityLines"] != true {
		t.Fatal(c)
	}
	// The wrong host is refused and changes nothing.
	if status, _ := pairingPost(t, client, `{"profile":"phone","lane":"sandbox","hostId":"other","e2e":null}`); status != 409 {
		t.Fatal(status)
	}
	if status := pairingStatus(t, client, "phone"); status["private"] != true {
		t.Fatal(status)
	}
	// `e2e: null` removes the key: back to the plaintext path, choice kept.
	if status, body := pairingPost(t, client, `{"profile":"phone","lane":"sandbox","hostId":"host","e2e":null}`); status != 200 ||
		!strings.Contains(body, `"private":false`) || !strings.Contains(body, `"liveActivityLines":true`) {
		t.Fatal(status, body)
	}
	c = storedCredential(t, creds, "phone")
	if _, ok := c["e2e"]; ok {
		t.Fatal(c)
	}
	if c["liveActivityLines"] != true || c["hostToken"] != strings.Repeat("a", 43) {
		t.Fatal(c)
	}
	if status := pairingStatus(t, client, "phone"); status["private"] != false {
		t.Fatal(status)
	}
	// Removing a key that is not there, and an empty update, are no-ops.
	if status, _ := pairingPost(t, client, `{"profile":"phone","lane":"sandbox","hostId":"host","e2e":null}`); status != 200 {
		t.Fatal(status)
	}
	if status, body := pairingPost(t, client, `{"profile":"phone","lane":"sandbox","hostId":"host"}`); status != 200 || !strings.Contains(body, `"paired":true`) {
		t.Fatal(status, body)
	}
	// Re-adding after removal works, and the pairing is private again.
	if status, _ := pairingPost(t, client, `{"profile":"phone","lane":"sandbox","hostId":"host","e2e":{"v":1,"pub":"`+second+`"}}`); status != 200 {
		t.Fatal(status)
	}
	if status := pairingStatus(t, client, "phone"); status["private"] != true || status["liveActivityLines"] != true {
		t.Fatal(status)
	}
	c = storedCredential(t, creds, "phone")
	if c["e2e"].(map[string]any)["pub"] != second {
		t.Fatal(c)
	}
	// A profile that was never paired is not created by an update, and a
	// different lane is refused.
	if status, _ := pairingPost(t, client, `{"profile":"nobody","lane":"sandbox","hostId":"host","e2e":{"v":1,"pub":"`+first+`"}}`); status != 409 {
		t.Fatal(status)
	}
	if _, err := os.Stat(filepath.Join(creds, "nobody.json")); !os.IsNotExist(err) {
		t.Fatal("an update created a pairing")
	}
	if status, _ := pairingPost(t, client, `{"profile":"phone","lane":"production","hostId":"host","liveActivityLines":false}`); status != 409 {
		t.Fatal(status)
	}
	if status := pairingStatus(t, client, "phone"); status["liveActivityLines"] != true {
		t.Fatal(status)
	}
}
