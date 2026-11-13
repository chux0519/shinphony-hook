package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"net.potafree/shinphony/hook/internal/notifier"
)

type hookEvent struct {
	ID      string      `json:"eventId"`
	Status  string      `json:"status"`
	Source  *hookSource `json:"source,omitempty"`
	Trigger string      `json:"trigger,omitempty"`
}

// Optional local-only acknowledgement. Old daemons omit ContextStatus; that
// remains unknown. Never infer a located target from a submitted Source.
type hookAcceptance struct {
	ContextStatus string `json:"contextStatus"`
	Destinations  *int   `json:"destinations,omitempty"`
	Queued        *bool  `json:"queued,omitempty"`
}

func decodeHookAcceptance(body []byte) hookAcceptance {
	result := hookAcceptance{ContextStatus: "unknown"}
	var wire hookAcceptance
	if len(body) > 4096 || json.Unmarshal(body, &wire) != nil {
		return result
	}
	if wire.ContextStatus == "resolved" || wire.ContextStatus == "unavailable" {
		result.ContextStatus = wire.ContextStatus
	}
	if wire.Destinations != nil && *wire.Destinations >= 0 {
		result.Destinations = wire.Destinations
	}
	result.Queued = wire.Queued
	return result
}
func postHook(ctx context.Context, dir string, e hookEvent) error {
	_, err := postHookResult(ctx, dir, e)
	return err
}
func postHookResult(ctx context.Context, dir string, e hookEvent) (hookAcceptance, error) {
	unknown := hookAcceptance{ContextStatus: "unknown"}
	body, _ := json.Marshal(e)
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://localhost/v1/hooks", bytes.NewReader(body))
	resp, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return unknown, err
	}
	defer resp.Body.Close()
	bodyResult, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if resp.StatusCode != 200 {
		if code := strings.TrimSpace(string(bodyResult)); identifier.MatchString(code) {
			return unknown, errors.New(code)
		}
		return unknown, errors.New("hook_queue_rejected")
	}
	if readErr != nil {
		return unknown, nil
	}
	return decodeHookAcceptance(bodyResult), nil
}
func hookCLI(kind string, args []string) {
	if kind == "codex-notify-chain" {
		if len(args) != 2 {
			return
		}
		original, err := notifier.DecodeComputerUseChain(args[0])
		if err != nil {
			return
		}
		// Parallel, independent branches: a hung original callback must not prevent
		// enqueue, and an unavailable daemon must not suppress Computer Use.
		done := make(chan struct{})
		go func() { defer close(done); forwardComputerUse(original, args[1]) }()
		hookCLI("codex-notify-all", []string{args[1]})
		<-done
		return
	}
	// A malformed hook or unreachable daemon must never block the agent loop.
	timer := time.AfterFunc(3*time.Second, func() { os.Exit(0) })
	defer timer.Stop()
	nativeHook := kind == "claude-hook-all" || kind == "dsh-hook-all" || kind == "codex-hook-all"
	var feedback map[string]any
	if nativeHook {
		// No decision: the agent proceeds (or asks in the terminal) as usual.
		defer func() {
			if feedback == nil {
				os.Stdout.WriteString("{}\n")
			} else {
				json.NewEncoder(os.Stdout).Encode(feedback)
			}
		}()
	}
	var raw []byte
	if kind == "codex-notify-all" {
		if len(args) != 1 {
			return
		}
		raw = []byte(args[0])
	} else {
		var err error
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 262145))
		if err != nil {
			return
		}
	}
	if kind == "codex-hook-all" {
		var h struct {
			Event string `json:"hook_event_name"`
		}
		if json.Unmarshal(raw, &h) == nil && h.Event == "PostToolUse" {
			exe, err := os.Executable()
			if err != nil {
				return
			}
			if _, ok := managedBinaryDigest(exe); !ok {
				return
			}
			// Ignore unrelated tools before process discovery or any IPC.
			if p, _, _, candidate := taskIntentCandidate(raw); !candidate {
				return
			} else if _, _, ok := parseTaskIntentHook(raw, exe); !ok {
				feedback = taskIntentFeedback(p, "not accepted (run task-intent alone in a separate shell tool call)")
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			owner := codexOwner(ctx, os.Getppid())
			feedback = forwardTaskIntent(ctx, raw, exe, owner, agentGetenv(ctx, owner, os.Getenv), discoverTaskPane, func(e hookEvent) (hookAcceptance, error) {
				return postHookResult(ctx, filepath.Dir(exe), e)
			})
			return
		}
	}
	var agentEv agentEvent
	var id, status string
	var ok bool
	if nativeHook {
		var h notifier.HookInfo
		if h, ok = notifier.ParseHook(raw); ok {
			agentEv, ok = agentEventFromHook(strings.TrimSuffix(kind, "-hook-all"), h, os.Getenv)
		}
	} else {
		id, status, ok = notifier.Extract(kind, raw)
	}
	if !ok {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	// Managed hooks always target an immutable binary in the daemon state dir.
	if _, ok := managedBinaryDigest(exe); !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if agentEv.Agent == "codex" {
		if h, ok := notifier.ParseHook(raw); ok {
			pid := os.Getppid()
			if owner := codexOwner(ctx, pid); owner > 1 {
				pid = owner
			}
			agentEv.Source = hookSourceFromEnv("codex", h.Session, pid, agentGetenv(ctx, pid, os.Getenv))
		}
	}
	if agentEv.Agent != "" {
		_ = postAgentEvent(ctx, dir, agentEv)
		return
	}
	var source *hookSource
	if kind == "codex-notify-all" {
		var p struct {
			Thread string `json:"thread-id"`
		}
		if json.Unmarshal(raw, &p) == nil {
			source = hookSourceFromEnv("codex", p.Thread, os.Getppid(), os.Getenv)
		}
	}
	_ = postHook(ctx, dir, hookEvent{ID: id, Status: status, Source: source})
}

func forwardComputerUse(original []string, payload string) {
	if !notifier.ComputerUseCommand(original) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	args := append(append([]string{}, original[1:]...), payload)
	cmd := exec.CommandContext(ctx, original[0], args...)
	// No shell; preserve argument boundaries, cwd and environment. No payload log.
	cmd.WaitDelay = 200 * time.Millisecond
	_ = cmd.Run()
}

// agentGetenv prefers the hook's own environment; when it carries no terminal
// identity (Codex's "core" environment policy), the agent process's is used.
func agentGetenv(ctx context.Context, pid int, getenv func(string) string) func(string) string {
	if getenv("HC_TERMINAL_ID") != "" || getenv("TMUX_PANE") != "" {
		return getenv
	}
	agent := processEnv(ctx, pid)
	return func(k string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return agent[k]
	}
}
