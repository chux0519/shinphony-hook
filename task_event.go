package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

// Explicit task completion, invoked by an agent only after the whole requested
// task is done. taskId is caller-owned and stable across retries, not a turn ID.
func explicitTaskEvent(dir string, input io.Reader) error {
	var p struct {
		TaskID string `json:"taskId"`
		Status string `json:"status"`
		Thread string `json:"thread,omitempty"`
	}
	d := json.NewDecoder(io.LimitReader(input, 4097))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || !identifier.MatchString(p.TaskID) ||
		(p.Thread != "" && !identifier.MatchString(p.Thread)) || !(Event{"p", p.TaskID, p.Status}).valid() {
		return errors.New("invalid_task_event")
	}
	e := explicitEvent(p.TaskID, p.Status, p.Thread)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// A shell invoked by Codex is short lived. Find the owning Codex process
	// instead of storing that shell's PID as the notification navigation target.
	if p.Thread != "" {
		if pid := codexOwner(ctx, os.Getppid()); pid > 1 {
			e.Source = resolveTaskSource(ctx, pid, p.Thread, agentGetenv(ctx, pid, os.Getenv), discoverTaskPane)
		}
	}
	return postHook(ctx, dir, e)
}

// Shared by direct IPC and native-hook handoff, so switching/retrying the
// transport cannot create a second completion for the same thread/task/status.
func explicitEvent(taskID, status, thread string) hookEvent {
	key, _ := json.Marshal([]string{thread, taskID, status})
	hash := sha256.Sum256(append([]byte("explicit-task-v1\x00"), key...))
	return hookEvent{ID: hex.EncodeToString(hash[:]), Status: status, Trigger: "explicit-task"}
}

// Shared source construction for both explicit transports. Discovery is injected
// only to keep tests isolated from the user's tmux server.
func resolveTaskSource(ctx context.Context, owner int, thread string, getenv func(string) string, discover func(context.Context, int) (string, string)) *hookSource {
	source := hookSourceFromEnv("codex", thread, owner, getenv)
	if source.HcAddress == "" && source.HcSocket == "" && (source.Tmux == "" || source.Pane == "") && ctx.Err() == nil {
		source.Tmux, source.Pane = discover(ctx, owner)
	}
	return source
}
