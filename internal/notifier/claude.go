package notifier

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func claudeConfigPath(home string) string {
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "settings.json")
	}
	return filepath.Join(home, ".claude", "settings.json")
}

// The daemon tracks each session's turns: prompt submission arms timing and
// "notify me" requests, Stop ends a turn, Notification asks for attention.
var claudeHooks = hookTarget{
	subcommand: "claude-hook-all",
	events:     []string{"SessionStart", "UserPromptSubmit", "Stop", "Notification", "SessionEnd", "PreToolUse"},
	// PreToolUse only for AskUserQuestion: its questions and options.
	matchers: map[string]string{"Notification": "permission_prompt|elicitation_dialog", "PreToolUse": "AskUserQuestion"},
	invalid:  "invalid_claude_config",
	// Claude Code runs a hook through PowerShell when asked to.
	windowsShellField: true,
}
var claudeHookEvents = claudeHooks.events

func stripClaude(before []byte) ([]byte, error) { return claudeHooks.strip(before) }
func proposedClaude(before []byte, exe string) ([]byte, error) {
	return claudeHooks.propose(before, exe)
}

func claudeEvent(raw []byte) (event, bool) {
	if len(raw) > 262144 {
		return event{}, false
	}
	var p struct {
		Hook    string `json:"hook_event_name"`
		Session string `json:"session_id"`
		Kind    string `json:"notification_type"`
		Active  bool   `json:"stop_hook_active"`
	}
	if json.Unmarshal(raw, &p) != nil || p.Session == "" || len(p.Session) > 512 {
		return event{}, false
	}
	status := ""
	switch {
	case p.Hook == "Notification" && (p.Kind == "permission_prompt" || p.Kind == "elicitation_dialog"):
		status = "attention"
	default:
		return event{}, false
	}
	// Claude supplies no stable turn ID here. A unique invocation ID avoids
	// collapsing separate turns; never read transcript or assistant text for IDs.
	return event{randomID(), status}, true
}
