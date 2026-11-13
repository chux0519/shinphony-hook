package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// `notify`, like `moshi-hook notify`: a push from scripts, CI and cron through
// the paired daemon. Best effort by default (always exits 0, so it never
// breaks the calling script); --strict waits for the relay and fails if the
// push was dropped.
type notifyRequest struct {
	Title   string `json:"title,omitempty"`
	Body    string `json:"body,omitempty"`
	Source  string `json:"source,omitempty"`
	Error   bool   `json:"error,omitempty"`
	Silent  bool   `json:"silent,omitempty"`
	EventID string `json:"eventId"`
}

func (r notifyRequest) valid() bool {
	return identifier.MatchString(r.EventID) && excerpt(r.Title, 80, false) == r.Title &&
		excerpt(r.Body, 200, true) == r.Body && excerpt(r.Source, 64, false) == r.Source && (r.Title != "" || r.Body != "")
}

// details maps a notification onto the relay's v2 event: the source names
// the card (project), errors are their own category.
func (r notifyRequest) details() (status string, d *eventDetails) {
	d = &eventDetails{Category: "task_complete", Title: r.Title, Body: r.Body, Project: r.Source, Visibility: "banner"}
	status = "completed"
	if r.Error {
		status, d.Category = "failed", "error"
	}
	if r.Silent {
		d.Visibility = "silent"
	}
	return status, d
}

func notifyCLI(dir string, args []string, stdin io.Reader, stderr io.Writer) int {
	fs := flag.NewFlagSet("notify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	title := fs.String("title", "", "title (default: first line of the message)")
	source := fs.String("source", "", "what sent it, shown with the notification")
	isErr := fs.Bool("error", false, "report a failure")
	silent := fs.Bool("silent", false, "update the inbox without a visible push")
	strict := fs.Bool("strict", false, "wait until the relay accepts it; exit 1 if dropped")
	if fs.Parse(args) != nil {
		return 2
	}
	message := strings.Join(fs.Args(), " ")
	if message == "" {
		if b, err := io.ReadAll(io.LimitReader(stdin, 65536)); err == nil {
			message = string(b)
		}
	}
	message = strings.TrimSpace(message)
	if *title == "" {
		first, rest, _ := strings.Cut(message, "\n")
		*title, message = first, strings.TrimSpace(rest)
	}
	r := notifyRequest{Title: excerpt(*title, 80, false), Body: excerpt(message, 200, true), Source: excerpt(*source, 64, false),
		Error: *isErr, Silent: *silent, EventID: eventID("notify", randomEventSeed())}
	fail := func(reason string) int {
		fmt.Fprintln(stderr, "notification not sent:", reason)
		if *strict {
			return 1
		}
		return 0
	}
	if r.Title == "" && r.Body == "" {
		fmt.Fprintln(stderr, "usage: notify [--title T] [--source S] [--error] [--silent] [--strict] MESSAGE (or on stdin)")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	body, _ := json.Marshal(r)
	resp, err := client.Post("http://local/v1/notify", "application/json", bytes.NewReader(body))
	if err != nil {
		return fail("the Shinphony service is not running")
	}
	var out struct {
		Queued bool   `json:"queued"`
		Reason string `json:"reason"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out)
	resp.Body.Close()
	if !out.Queued {
		if out.Reason == "" {
			out.Reason = resp.Status
		}
		return fail(out.Reason)
	}
	if !*strict {
		return 0
	}
	// Through the daemon's retries, up to about 40 seconds (as Moshi does).
	for {
		state, code, err := notifyState(ctx, client, r.EventID)
		switch {
		case err != nil:
			return fail("status unavailable")
		case state == "sent":
			return 0
		case state == "failed" || state == "suppressed":
			return fail(code)
		}
		select {
		case <-ctx.Done():
			return fail("not confirmed within 45 seconds")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func notifyState(ctx context.Context, client *http.Client, id string) (state, code string, err error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://local/v1/notify/"+id, nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var out struct{ State, Code string }
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out) != nil {
		return "", "", errors.New("status_unavailable")
	}
	return out.State, out.Code, nil
}

func randomEventSeed() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%d", b, time.Now().UnixNano())
}
