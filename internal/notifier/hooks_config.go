package notifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
)

// hookTarget is a Claude Code-format hooks document we add our handlers to:
// Claude Code's settings.json and Codex's hooks.json share the shape
// {"hooks": {Event: [{"matcher"?, "hooks": [{"type","command","timeout"}]}]}}.
// Our handlers are recognised by their subcommand, so other tools' hooks and
// later edits survive install, upgrade and uninstall.
type hookTarget struct {
	subcommand string
	events     []string
	matchers   map[string]string
	invalid    string
	// windowsShellField: the agent honours "shell": "powershell" per handler.
	windowsShellField bool
}

func (t hookTarget) ours(command string) bool {
	return strings.HasSuffix(strings.TrimSpace(command), " "+t.subcommand)
}

// strip removes our handlers, then any group or event left empty. A file
// without them is returned unchanged, byte for byte.
func (t hookTarget) strip(before []byte) ([]byte, error) {
	doc := map[string]json.RawMessage{}
	if len(before) == 0 || !bytes.Contains(before, []byte(t.subcommand)) {
		return before, nil
	}
	if json.Unmarshal(before, &doc) != nil || doc == nil {
		return nil, errors.New(t.invalid)
	}
	hooks := map[string][]map[string]json.RawMessage{}
	if json.Unmarshal(doc["hooks"], &hooks) != nil {
		return nil, errors.New(t.invalid)
	}
	removed := false
	for event, groups := range hooks {
		kept := groups[:0]
		for _, group := range groups {
			var handlers []map[string]any
			if json.Unmarshal(group["hooks"], &handlers) != nil {
				return nil, errors.New(t.invalid)
			}
			left := handlers[:0]
			for _, h := range handlers {
				if command, _ := h["command"].(string); t.ours(command) {
					removed = true
					continue
				}
				left = append(left, h)
			}
			if len(left) == 0 {
				continue
			}
			group["hooks"], _ = json.Marshal(left)
			kept = append(kept, group)
		}
		if len(kept) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = kept
		}
	}
	if !removed {
		return before, nil
	}
	if len(hooks) == 0 {
		delete(doc, "hooks")
	} else {
		doc["hooks"], _ = json.Marshal(hooks)
	}
	return json.MarshalIndent(doc, "", "  ")
}

func (t hookTarget) propose(before []byte, exe string) ([]byte, error) {
	before, err := t.strip(before)
	if err != nil {
		return nil, err
	}
	doc := map[string]json.RawMessage{}
	if len(before) > 0 && (json.Unmarshal(before, &doc) != nil || doc == nil) {
		return nil, errors.New(t.invalid)
	}
	// Respect explicitly disabled or managed hooks instead of claiming success.
	if string(doc["disableAllHooks"]) == "true" || string(doc["allowManagedHooksOnly"]) == "true" {
		return nil, errors.New("hooks_disabled")
	}
	hooks := map[string]json.RawMessage{}
	if raw, ok := doc["hooks"]; ok && (json.Unmarshal(raw, &hooks) != nil || hooks == nil) {
		return nil, errors.New(t.invalid)
	}
	// Permission rules or project paths may contain our name; only an
	// existing hook (e.g. the old notify.py skill) would duplicate notifications.
	if lower := bytes.ToLower(doc["hooks"]); bytes.Contains(lower, []byte("shinphony")) || bytes.Contains(lower, []byte("notify.py")) {
		return nil, errors.New("existing_shinphony_config")
	}
	handler := map[string]any{"type": "command", "command": "'" + strings.ReplaceAll(exe, "'", "'\\''") + "' " + t.subcommand, "timeout": 6}
	if runtime.GOOS == "windows" {
		handler["command"] = "& '" + strings.ReplaceAll(exe, "'", "''") + "' " + t.subcommand
		if t.windowsShellField {
			handler["shell"] = "powershell"
		}
	}
	for _, event := range t.events {
		var entries []json.RawMessage
		if raw, ok := hooks[event]; ok && (json.Unmarshal(raw, &entries) != nil || entries == nil) {
			return nil, errors.New(t.invalid)
		}
		entry := map[string]any{"hooks": []any{handler}}
		if m := t.matchers[event]; m != "" {
			entry["matcher"] = m
		}
		b, _ := json.Marshal(entry)
		entries = append(entries, b)
		hooks[event], _ = json.Marshal(entries)
	}
	doc["hooks"], _ = json.Marshal(hooks)
	return json.MarshalIndent(doc, "", "  ")
}
