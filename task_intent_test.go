package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func intentHook(command, output string) []byte {
	b, _ := json.Marshal(map[string]any{"hook_event_name": "PostToolUse", "tool_name": "Bash", "session_id": "runtime-thread", "tool_input": map[string]string{"command": command}, "tool_response": output})
	return b
}
func TestTaskIntentValidatedStandaloneCommand(t *testing.T) {
	exe := "/private/test's/shinphony-hook-" + strings.Repeat("a", 64)
	output, err := taskIntentOutput([]string{"task_1", "completed"})
	if err != nil {
		t.Fatal(err)
	}
	for _, windows := range []bool{false, true} {
		raw := intentHook(taskIntentCommand(exe, "task_1", "completed", windows), output)
		p, thread, ok := parseTaskIntentHook(raw, exe)
		if !ok || p.TaskID != "task_1" || p.Status != "completed" || thread != "runtime-thread" {
			t.Fatalf("intent rejected: %v %s %v", p, thread, ok)
		}
	}
}
func TestTaskIntentRejectsUnrelatedOrForgedOutput(t *testing.T) {
	exe := "/private/bin/shinphony-hook-" + strings.Repeat("a", 64)
	output, _ := taskIntentOutput([]string{"task", "completed"})
	command := taskIntentCommand(exe, "task", "completed", false)
	valid := intentHook(command, output)
	cases := [][]byte{
		intentHook("printf '"+output+"'", output),
		intentHook("echo x; "+command, output),
		intentHook(command+"\necho x", output),
		intentHook(command+" && true", output),
		intentHook(strings.Replace(command, exe, "/workspace/fake", 1), output),
		intentHook(command, "log\n"+output),
		intentHook(command, output+output),
		intentHook(command, strings.Replace(output, "completed", "attention", 1)),
		[]byte(strings.Replace(string(valid), "PostToolUse", "Stop", 1)),
		[]byte(strings.Replace(string(valid), "runtime-thread", "../other", 1)),
		[]byte(strings.Replace(string(valid), `"Bash"`, `"apply_patch"`, 1)),
		[]byte(strings.Replace(string(valid), `"tool_response":`, `"tool_response":{},"ignored":`, 1)),
		[]byte(strings.Repeat("x", 262145)),
	}
	for i, raw := range cases {
		if _, _, ok := parseTaskIntentHook(raw, exe); ok {
			t.Fatalf("accepted case %d", i)
		}
	}
}
func TestTaskIntentBoundedPublicFields(t *testing.T) {
	for _, args := range [][]string{nil, {"x"}, {"x", "completed", "thread"}, {"../bad", "completed"}, {strings.Repeat("x", 65), "completed"}, {"x", "working"}, {"x", "completed;cmd"}} {
		if _, e := taskIntentOutput(args); e == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, status := range []string{"completed", "attention", "failed"} {
		out, e := taskIntentOutput([]string{"task", status})
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(out, "pending") || strings.Contains(out, "accepted") {
			t.Fatal("claimed delivery", out)
		}
	}
}

func TestTaskIntentForwardingAndRetryIdentity(t *testing.T) {
	exe := "/private/bin/shinphony-hook-" + strings.Repeat("a", 64)
	output, _ := taskIntentOutput([]string{"stable", "completed"})
	raw := intentHook(taskIntentCommand(exe, "stable", "completed", false), output)
	seen := []hookEvent{}
	send := func(e hookEvent) (hookAcceptance, error) {
		seen = append(seen, e)
		queued := true
		return hookAcceptance{Queued: &queued}, nil
	}
	getenv := func(key string) string {
		if key == "HC_TERMINAL_ID" {
			return "t1"
		}
		if key == "HC_TERMINAL_SOCKET" {
			return "/private/hc.sock"
		}
		return ""
	}
	for i := 0; i < 2; i++ {
		feedback := forwardTaskIntent(context.Background(), raw, exe, 42, getenv, discoverTaskPane, send)
		if !strings.Contains(feedback["systemMessage"].(string), "accepted locally") {
			t.Fatal(feedback)
		}
		if feedback["hookSpecificOutput"] == nil {
			t.Fatal("missing model feedback")
		}
	}
	direct := explicitEvent("stable", "completed", "runtime-thread")
	if len(seen) != 2 || seen[0].ID != direct.ID || seen[1].ID != direct.ID || seen[0].Trigger != "explicit-task" {
		t.Fatal(seen)
	}
	source := seen[0].Source
	if source.Thread != "runtime-thread" || source.ParentPID != 42 || source.HcAddress != "t1" || source.HcSocket != "/private/hc.sock" {
		t.Fatal(source)
	}
	// No Codex owner and arbitrary tool output cannot reach the daemon.
	forwardTaskIntent(context.Background(), raw, exe, 0, getenv, discoverTaskPane, send)
	forwardTaskIntent(context.Background(), intentHook("echo x", output), exe, 42, getenv, discoverTaskPane, send)
	if len(seen) != 2 {
		t.Fatal("unsafe forwarding")
	}
	feedback := forwardTaskIntent(context.Background(), raw, exe, 42, getenv, discoverTaskPane, func(hookEvent) (hookAcceptance, error) { return hookAcceptance{}, errors.New("unavailable") })
	if !strings.Contains(feedback["systemMessage"].(string), "not accepted") {
		t.Fatal(feedback)
	}
}

func TestTaskIntentCompoundRequestGetsFailureFeedback(t *testing.T) {
	exe := "/private/bin/shinphony-hook-" + strings.Repeat("a", 64)
	output, _ := taskIntentOutput([]string{"task", "completed"})
	command := "printf done; " + taskIntentCommand(exe, "task", "completed", false)
	feedback := forwardTaskIntent(context.Background(), intentHook(command, output), exe, 42, func(string) string { return "" }, discoverTaskPane, func(hookEvent) (hookAcceptance, error) {
		t.Fatal("compound command forwarded")
		return hookAcceptance{}, nil
	})
	if feedback == nil || !strings.Contains(feedback["systemMessage"].(string), "not accepted") {
		t.Fatal("missing rejection", feedback)
	}
}

func TestTaskIntentLiteralDoubleQuotedPaths(t *testing.T) {
	output, _ := taskIntentOutput([]string{"task", "completed"})
	for _, tc := range []struct{ exe, command, bad string }{
		{"/tmp/plain/bin", `"/tmp/plain/bin" task-intent task completed`, `"/tmp/plain/bin" task-intent task completed; true`},
		{"/tmp/space/$literal", `"/tmp/space/\$literal" task-intent task completed`, `"/tmp/space/$literal" task-intent task completed`},
		{`C:\space\$literal.exe`, `& "C:\space\` + "`" + `$literal.exe" task-intent task completed`, `& "C:\space\$literal.exe" task-intent task completed`},
	} {
		if _, _, ok := parseTaskIntentHook(intentHook(tc.command, output), tc.exe); !ok {
			t.Fatal("literal rejected", tc.command)
		}
		if _, _, ok := parseTaskIntentHook(intentHook(tc.bad, output), tc.exe); ok {
			t.Fatal("unsafe command accepted", tc.bad)
		}
	}
}
