package notifier

import (
	"bytes"
	"encoding/json"
	"strings"
)

// HookInfo is what the daemon needs from a Claude Code-format hook payload
// (Claude Code itself and the DSH bridge). Like Moshi, bounded excerpts of
// the prompt, reply and notification message become the notification text.
type HookInfo struct {
	Event   string
	Session string
	Cwd     string
	Kind    string
	Prompt  string
	Reply   string
	Message string
	Tool    string
	// Command is the tool input: its "command" for shell tools, else compact JSON.
	Command string
	Active  bool
	// Questions the agent asks the user through a tool: Codex request_user_input
	// (sync) and request_user_input_async, Claude Code AskUserQuestion.
	Questions []Question
}

// Question is one question with its suggested answers, in display order.
type Question struct {
	Text    string
	Options []string
}

// QuestionTool reports a tool whose input is a set of questions for the user.
func QuestionTool(name string) bool {
	return name == "request_user_input" || name == "request_user_input_async" || name == "AskUserQuestion"
}

// parseQuestions reads every known shape: {title, options: [string]} (Codex
// async), {question, options: [{label, description}]} (Codex sync, Claude).
func parseQuestions(input json.RawMessage) []Question {
	var p struct {
		Questions []struct {
			Title    string            `json:"title"`
			Question string            `json:"question"`
			Header   string            `json:"header"`
			Options  []json.RawMessage `json:"options"`
		} `json:"questions"`
	}
	if json.Unmarshal(input, &p) != nil {
		return nil
	}
	var out []Question
	for _, q := range p.Questions {
		text := strings.TrimSpace(q.Title)
		if text == "" {
			text = strings.TrimSpace(q.Question)
		}
		if text == "" {
			text = strings.TrimSpace(q.Header)
		}
		if text == "" {
			continue
		}
		item := Question{Text: text}
		for _, raw := range q.Options {
			var label string
			if json.Unmarshal(raw, &label) != nil {
				var o struct {
					Label string `json:"label"`
				}
				if json.Unmarshal(raw, &o) == nil {
					label = o.Label
				}
			}
			if label = strings.TrimSpace(label); label != "" && len(item.Options) < 8 {
				item.Options = append(item.Options, label)
			}
		}
		out = append(out, item)
		if len(out) == 4 {
			break
		}
	}
	return out
}

func ParseHook(raw []byte) (HookInfo, bool) {
	if len(raw) > 262144 {
		return HookInfo{}, false
	}
	var p struct {
		Event   string          `json:"hook_event_name"`
		Session string          `json:"session_id"`
		Cwd     string          `json:"cwd"`
		Kind    string          `json:"notification_type"`
		Prompt  string          `json:"prompt"`
		Reply   string          `json:"last_assistant_message"`
		Message string          `json:"message"`
		Tool    string          `json:"tool_name"`
		Input   json.RawMessage `json:"tool_input"`
		Active  bool            `json:"stop_hook_active"`
	}
	if json.Unmarshal(raw, &p) != nil || p.Event == "" || p.Session == "" || len(p.Session) > 512 {
		return HookInfo{}, false
	}
	h := HookInfo{Event: p.Event, Session: p.Session, Cwd: p.Cwd, Kind: p.Kind, Prompt: p.Prompt, Reply: p.Reply, Message: p.Message, Tool: p.Tool, Active: p.Active}
	if QuestionTool(p.Tool) {
		h.Questions = parseQuestions(p.Input)
	}
	var shell struct {
		Command any `json:"command"`
	}
	if json.Unmarshal(p.Input, &shell) == nil {
		switch c := shell.Command.(type) {
		case string:
			h.Command = c
		case []any:
			parts := make([]string, 0, len(c))
			for _, a := range c {
				if s, ok := a.(string); ok {
					parts = append(parts, s)
				}
			}
			h.Command = strings.Join(parts, " ")
		}
	}
	if h.Command == "" && len(p.Input) > 0 && string(p.Input) != "null" {
		var compact bytes.Buffer
		if json.Compact(&compact, p.Input) == nil {
			h.Command = compact.String()
		}
	}
	return h, true
}
