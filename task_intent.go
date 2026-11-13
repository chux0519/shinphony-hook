package main

// A trusted Codex PostToolUse handler forwards a deliberately narrow explicit
// task request. The sandboxed CLI only emits a pending request, never success.
import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

type taskIntent struct {
	TaskID string `json:"taskId"`
	Status string `json:"status"`
}

func (p taskIntent) valid() bool {
	return identifier.MatchString(p.TaskID) && (Event{"p", p.TaskID, p.Status}).valid()
}
func taskIntentOutput(args []string) (string, error) {
	if len(args) != 2 {
		return "", errors.New("usage: task-intent TASK_ID completed|attention|failed")
	}
	p := taskIntent{args[0], args[1]}
	if !p.valid() {
		return "", errors.New("invalid_task_intent")
	}
	b, _ := json.Marshal(struct {
		Version int    `json:"shinphonyTaskIntent"`
		State   string `json:"state"`
		taskIntent
	}{1, "pending", p})
	return string(b) + "\n", nil
}
func taskIntentCommand(exe, task, status string, windows bool) string {
	quoted := "'" + strings.ReplaceAll(exe, "'", "'\\''") + "'"
	if windows {
		quoted = "& '" + strings.ReplaceAll(exe, "'", "''") + "'"
	}
	return quoted + " task-intent " + task + " " + status
}
func taskIntentCandidate(raw []byte) (taskIntent, string, string, bool) {
	var h struct {
		Event  string `json:"hook_event_name"`
		Tool   string `json:"tool_name"`
		Thread string `json:"session_id"`
		Input  struct {
			Command string `json:"command"`
		} `json:"tool_input"`
		Output string `json:"tool_response"`
	}
	if len(raw) > 262144 || json.Unmarshal(raw, &h) != nil || h.Event != "PostToolUse" || h.Tool != "Bash" || !identifier.MatchString(h.Thread) || len(h.Output) > 512 {
		return taskIntent{}, "", "", false
	}
	var p taskIntent
	if json.Unmarshal([]byte(h.Output), &p) != nil || !p.valid() {
		return taskIntent{}, "", "", false
	}
	expected, _ := taskIntentOutput([]string{p.TaskID, p.Status})
	if strings.TrimSpace(h.Output) != strings.TrimSpace(expected) {
		return taskIntent{}, "", "", false
	}
	return p, h.Thread, strings.TrimSpace(h.Input.Command), true
}
func parseTaskIntentHook(raw []byte, exe string) (taskIntent, string, bool) {
	p, thread, command, ok := taskIntentCandidate(raw)
	if !ok {
		return taskIntent{}, "", false
	}
	suffix := " task-intent " + p.TaskID + " " + p.Status
	// Exact literal spellings only: do not parse/evaluate arbitrary shell text.
	shDouble := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`").Replace(exe)
	psDouble := strings.NewReplacer("`", "``", `"`, "`\"", "$", "`$").Replace(exe)
	for _, allowed := range []string{taskIntentCommand(exe, p.TaskID, p.Status, false), taskIntentCommand(exe, p.TaskID, p.Status, true), `"` + shDouble + `"` + suffix, `& "` + psDouble + `"` + suffix} {
		if command == allowed {
			return p, thread, true
		}
	}
	return taskIntent{}, "", false
}
func taskIntentFeedback(p taskIntent, state string) map[string]any {
	message := "Shinphony task " + p.TaskID + ": " + state + "; phone delivery unverified."
	return map[string]any{"systemMessage": message, "hookSpecificOutput": map[string]any{"hookEventName": "PostToolUse", "additionalContext": message}}
}

// The caller supplies the real Codex owner PID, never a PID or thread from the
// tool's request. All existing daemon context checks and deduplication apply.
func forwardTaskIntent(ctx context.Context, raw []byte, exe string, owner int, getenv func(string) string, discover func(context.Context, int) (string, string), submit func(hookEvent) (hookAcceptance, error)) map[string]any {
	p, _, _, candidate := taskIntentCandidate(raw)
	if !candidate {
		return nil
	}
	_, thread, ok := parseTaskIntentHook(raw, exe)
	feedback := func(state string) map[string]any { return taskIntentFeedback(p, state) }
	if !ok {
		return feedback("not accepted (run task-intent alone in a separate shell tool call)")
	}
	if owner <= 1 {
		return feedback("not accepted (Codex owner unavailable)")
	}
	e := explicitEvent(p.TaskID, p.Status, thread)
	e.Source = resolveTaskSource(ctx, owner, thread, getenv, discover)
	accepted, err := submit(e)
	if err != nil || (accepted.Queued != nil && !*accepted.Queued) {
		return feedback("not accepted (local daemon unavailable or rejected request)")
	}
	if accepted.Queued == nil {
		return feedback("local acceptance unverified (no valid daemon acknowledgement)")
	}
	location := "terminal location unknown"
	switch accepted.ContextStatus {
	case "resolved":
		location = "terminal location resolved"
	case "unavailable":
		location = "terminal location unavailable; cannot return directly to the original session"
	}
	if accepted.Destinations != nil && *accepted.Destinations == 0 {
		location += "; no paired phone destinations"
	}
	return feedback("accepted locally; " + location)
}
