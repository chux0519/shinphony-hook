package notifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Google Antigravity (internal ID "agy") keeps its hooks in one JSON document
// that maps named groups to their event handlers:
//
//	{"group": {"enabled": true,
//	  "SessionStart": [{"type":"command","command":"...","timeout":6}],
//	  "PreToolUse": [{"matcher":"ask_question","hooks":[{"command":"..."}]}]}}
//
// The CLI, the App and the IDE all read ~/.gemini/config/hooks.json, so we
// maintain one group of ours there and leave every other group byte-identical.
// SessionStart, PreInvocation, PreToolUse, PostToolUse and Stop take handlers
// directly; only the two tool events take a matcher wrapper.
const (
	agyGroup = "shinphony"
	agySub   = "agy-hook"
	// Tool events are installed only for the two tools that ask the user
	// something: an ordinary tool call says nothing about waiting for approval.
	agyToolMatcher = "ask_question|ask_permission"
)

var agyEvents = []string{"SessionStart", "PreInvocation", "PreToolUse", "PostToolUse", "Stop"}

// agyToolEvents are the events whose entries are {"matcher","hooks":[...]}.
var agyToolEvents = map[string]bool{"PreToolUse": true, "PostToolUse": true}

func agyConfigPath(home string) string {
	return filepath.Join(home, ".gemini", "config", "hooks.json")
}

// agyDataDirs are Antigravity's own per-UI data directories. ~/.gemini alone
// is shared with the Gemini CLI, so its presence never means agy is installed.
var agyDataDirs = []string{"antigravity-cli", "antigravity", "antigravity-ide"}

// agyDetected reports the agy CLI or its own data directory, never the shared
// .gemini/config directory or another .gemini consumer.
func agyDetected(home string) bool {
	if _, err := exec.LookPath("agy"); err == nil {
		return true
	}
	for _, name := range agyDataDirs {
		if info, err := os.Stat(filepath.Join(home, ".gemini", name)); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

// agyHookCommand builds the exact command line the agent runs. Antigravity
// passes hook commands to cmd.exe unchanged on Windows (changelog item for
// escaping such as "C:\my dir\deny.json") and to a POSIX shell elsewhere, so
// Windows quoting is cmd-compatible double quotes, not PowerShell's `&`.
func agyHookCommand(goos, exe, event string) string {
	if goos == "windows" {
		return `"` + strings.ReplaceAll(exe, `"`, `""`) + `" ` + agySub + ` ` + event
	}
	return "'" + strings.ReplaceAll(exe, "'", `'\''`) + "' " + agySub + " " + event
}

// agyOwned reports whether one command is exactly the handler this daemon
// wrote for exe. Ownership is the exact command (both platform quotings), never
// a filename prefix or a bare `agy-hook` suffix, so a third-party command that
// merely looks similar is never claimed.
func agyOwned(command string, exes ...string) bool {
	if command == "" {
		return false
	}
	for _, exe := range exes {
		if exe == "" {
			continue
		}
		for _, goos := range []string{"darwin", "windows"} {
			for _, event := range agyEvents {
				if command == agyHookCommand(goos, exe, event) {
					return true
				}
			}
		}
	}
	return false
}

// agyPathError rejects executable paths the installed shell cannot run. Windows
// cmd.exe expands %NAME% even inside double quotes and exposes CR/LF/quote
// injection, so those are refused in preflight; spaces stay supported on both
// platforms and POSIX apostrophes remain escaped. Runtime quoting itself is
// still unverified on Windows.
func agyPathError(goos, exe string) error {
	if exe == "" || !agyAbsPath(goos, exe) {
		return errors.New("unsupported_agent_path")
	}
	if strings.ContainsAny(exe, "\x00\r\n") {
		return errors.New("unsupported_agent_path")
	}
	if goos == "windows" && strings.ContainsAny(exe, `%"`) {
		return errors.New("unsupported_windows_path")
	}
	return nil
}

// proposedAgy adds our group, keeping every other group as raw JSON. A group
// with our name but foreign content, another group that already runs a
// shinphony hook writer, or an explicitly disabled group is a conflict: the
// installer stops instead of guessing.
func proposedAgy(before []byte, exe string) ([]byte, error) {
	return agyProposal(runtime.GOOS, nil, before, exe)
}

// agyProposal adds our group for one platform. recordedExe is the executable
// the journal says our handlers were written with; only that exact command is
// removed from our own group. Every other group is left untouched.
func agyProposal(goos string, recorded []string, before []byte, exe string) ([]byte, error) {
	if err := agyPathError(goos, exe); err != nil {
		return nil, err
	}
	original := map[string]json.RawMessage{}
	if len(before) > 0 && (json.Unmarshal(before, &original) != nil || original == nil) {
		return nil, errors.New("invalid_agy_config")
	}
	if raw, ok := original[agyGroup]; ok {
		var group map[string]json.RawMessage
		if json.Unmarshal(raw, &group) != nil || group == nil {
			return nil, errors.New("invalid_agy_config")
		}
		// Respect an explicit disable instead of silently re-enabling it.
		if string(group["enabled"]) == "false" {
			return nil, errors.New("hooks_disabled")
		}
	}
	base, err := agyStrip(before, recorded...)
	if err != nil {
		return nil, err
	}
	// Another group that already runs our exact command would double every
	// event. That is a duplicate writer: stop instead of deleting it.
	if outside, err := agyOwnedOutside(base, recorded); err != nil {
		return nil, err
	} else if outside {
		return nil, errors.New("existing_shinphony_config")
	}
	doc := map[string]json.RawMessage{}
	if len(base) > 0 && (json.Unmarshal(base, &doc) != nil || doc == nil) {
		return nil, errors.New("invalid_agy_config")
	}
	lower := bytes.ToLower(base)
	if bytes.Contains(lower, []byte("shinphony")) || bytes.Contains(lower, []byte("notify.py")) {
		return nil, errors.New("existing_shinphony_config")
	}
	group := map[string]json.RawMessage{}
	for _, event := range agyEvents {
		handler := map[string]any{"type": "command", "command": agyHookCommand(goos, exe, event), "timeout": 6}
		var entry any = handler
		if agyToolEvents[event] {
			entry = map[string]any{"matcher": agyToolMatcher, "hooks": []any{handler}}
		}
		raw, err := json.Marshal([]any{entry})
		if err != nil {
			return nil, errConfig
		}
		group[event] = raw
	}
	if raw, err := json.Marshal(group); err != nil {
		return nil, errConfig
	} else {
		doc[agyGroup] = raw
	}
	return json.MarshalIndent(doc, "", "  ")
}

// agyStrip removes exactly the handlers this daemon wrote (exe from the
// install journal), only inside our own named group, then the group itself if
// it held nothing else. A document without our group is returned unchanged;
// foreign groups and a same-named group we cannot prove we own are never
// touched (installation then stops with a conflict).
func agyStrip(before []byte, exes ...string) ([]byte, error) {
	if len(before) == 0 || !bytes.Contains(before, []byte(agyGroup)) {
		return before, nil
	}
	doc := map[string]json.RawMessage{}
	if json.Unmarshal(before, &doc) != nil || doc == nil {
		return nil, errors.New("invalid_agy_config")
	}
	raw, ok := doc[agyGroup]
	if !ok {
		return before, nil
	}
	var group map[string]json.RawMessage
	if json.Unmarshal(raw, &group) != nil || group == nil {
		return nil, errors.New("invalid_agy_config")
	}
	removed := false
	for _, event := range agyEvents {
		eventRaw, ok := group[event]
		if !ok {
			continue
		}
		var entries []json.RawMessage
		if json.Unmarshal(eventRaw, &entries) != nil || entries == nil {
			return nil, errors.New("invalid_agy_config")
		}
		kept := make([]json.RawMessage, 0, len(entries))
		changed := false
		for _, entry := range entries {
			out, keep, touched, err := stripAgyEntry(entry, event, exes)
			if err != nil {
				return nil, err
			}
			if touched {
				changed = true
			}
			if keep {
				kept = append(kept, out)
			}
		}
		if !changed {
			continue
		}
		removed = true
		if len(kept) == 0 {
			delete(group, event)
			continue
		}
		encoded, err := json.Marshal(kept)
		if err != nil {
			return nil, errConfig
		}
		group[event] = encoded
	}
	if !removed {
		return before, nil
	}
	// A group that held only our handlers goes away; a group with any remaining
	// key (another event, "enabled", unknown fields) stays.
	empty := true
	for key := range group {
		if key != "enabled" {
			empty = false
			break
		}
	}
	if empty {
		delete(doc, agyGroup)
	} else {
		encoded, err := json.Marshal(group)
		if err != nil {
			return nil, errConfig
		}
		doc[agyGroup] = encoded
	}
	return json.MarshalIndent(doc, "", "  ")
}

// agyAbsPath checks absolute form for the target platform, not the host's.
func agyAbsPath(goos, p string) bool {
	if goos == "windows" {
		if strings.HasPrefix(p, `\\`) {
			return true
		}
		return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
	}
	return strings.HasPrefix(p, "/")
}

// agyOwnedOutside reports whether a group other than ours runs a command this
// daemon owns. Foreign groups are never modified, so the installer must stop.
func agyOwnedOutside(before []byte, exes []string) (bool, error) {
	return agyScanOwned(before, exes, true)
}

// agyContainsOwned reports whether any group still runs a command we wrote,
// including our own group. Uninstall uses it to refuse when it could not prove
// what to remove instead of dropping the recovery journal.
func agyContainsOwned(before []byte, exes []string) (bool, error) {
	return agyScanOwned(before, exes, false)
}

func agyScanOwned(before []byte, exes []string, skipOurGroup bool) (bool, error) {
	if len(exes) == 0 || len(before) == 0 {
		return false, nil
	}
	doc := map[string]json.RawMessage{}
	if json.Unmarshal(before, &doc) != nil || doc == nil {
		return false, errors.New("invalid_agy_config")
	}
	for name, raw := range doc {
		if skipOurGroup && name == agyGroup {
			continue
		}
		var group map[string]json.RawMessage
		if json.Unmarshal(raw, &group) != nil || group == nil {
			// Top-level metadata (numbers, strings) is not a hook group.
			continue
		}
		for _, event := range agyEvents {
			eventRaw, ok := group[event]
			if !ok {
				continue
			}
			var entries []json.RawMessage
			if json.Unmarshal(eventRaw, &entries) != nil || entries == nil {
				return false, errors.New("invalid_agy_config")
			}
			for _, entry := range entries {
				found, err := agyEntryOwned(entry, event, exes)
				if err != nil {
					return false, err
				}
				if found {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// agyEntryOwned reports whether one entry runs a command we wrote.
func agyEntryOwned(raw json.RawMessage, event string, exes []string) (bool, error) {
	if agyToolEvents[event] {
		var entry map[string]json.RawMessage
		if json.Unmarshal(raw, &entry) != nil || entry == nil {
			return false, errors.New("invalid_agy_config")
		}
		hooksRaw, ok := entry["hooks"]
		if !ok {
			return false, nil
		}
		var handlers []json.RawMessage
		if json.Unmarshal(hooksRaw, &handlers) != nil || handlers == nil {
			return false, errors.New("invalid_agy_config")
		}
		for _, handler := range handlers {
			var h struct {
				Command string `json:"command"`
			}
			if json.Unmarshal(handler, &h) != nil {
				return false, errors.New("invalid_agy_config")
			}
			if agyOwned(h.Command, exes...) {
				return true, nil
			}
		}
		return false, nil
	}
	var handler struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(raw, &handler) != nil {
		return false, errors.New("invalid_agy_config")
	}
	return agyOwned(handler.Command, exes...), nil
}

// stripAgyEntry reports whether to keep one entry and whether it lost a handler
// this daemon owns. A tool entry that mixed our handler with another tool's
// keeps the filtered entry: removing the whole wrapper would delete foreign
// handlers.
func stripAgyEntry(raw json.RawMessage, event string, exes []string) (out json.RawMessage, keep, touched bool, err error) {
	if agyToolEvents[event] {
		var entry map[string]json.RawMessage
		if json.Unmarshal(raw, &entry) != nil || entry == nil {
			return nil, false, false, errors.New("invalid_agy_config")
		}
		hooksRaw, ok := entry["hooks"]
		if !ok {
			return raw, true, false, nil
		}
		var handlers []json.RawMessage
		if json.Unmarshal(hooksRaw, &handlers) != nil || handlers == nil {
			return nil, false, false, errors.New("invalid_agy_config")
		}
		kept := make([]json.RawMessage, 0, len(handlers))
		for _, handler := range handlers {
			var h struct {
				Command string `json:"command"`
			}
			if json.Unmarshal(handler, &h) != nil {
				return nil, false, false, errors.New("invalid_agy_config")
			}
			if agyOwned(h.Command, exes...) {
				continue
			}
			kept = append(kept, handler)
		}
		if len(kept) == len(handlers) {
			return raw, true, false, nil
		}
		if len(kept) == 0 {
			return nil, false, true, nil
		}
		encoded, err := json.Marshal(kept)
		if err != nil {
			return nil, false, false, errConfig
		}
		entry["hooks"] = encoded
		filtered, err := json.Marshal(entry)
		return filtered, true, true, err
	}
	var handler struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(raw, &handler) != nil {
		return nil, false, false, errors.New("invalid_agy_config")
	}
	if agyOwned(handler.Command, exes...) {
		return nil, false, true, nil
	}
	return raw, true, false, nil
}

func (s store) configureAgy(path, exe string, apply bool) error {
	// Reject a path the agent's shell cannot run before creating or changing
	// anything, including in preflight.
	if err := agyPathError(runtime.GOOS, exe); err != nil {
		return err
	}
	if apply {
		// Antigravity's CLI creates ~/.gemini on first use; when only the CLI is
		// installed, create the shared parent privately. An existing .gemini
		// (Gemini CLI or agy) is never touched, and preflight never creates it.
		parent := filepath.Dir(filepath.Dir(path))
		if _, err := os.Lstat(parent); os.IsNotExist(err) {
			if err := checkParents(filepath.Dir(parent)); err != nil {
				return err
			}
			if err := makePrivateDir(parent); err != nil {
				return err
			}
		} else if err != nil {
			return errUnsafe
		}
	}
	// The journal is read inside the callbacks: configureAgentWith and
	// uninstallAgentWith hold the install lock when they call them, so a
	// concurrent completed install cannot leave ownership stale.
	propose := func(before []byte, newExe string) ([]byte, error) {
		return agyProposal(runtime.GOOS, s.agyRecordedExecutables(), before, newExe)
	}
	strip := func(before []byte) ([]byte, error) { return agyStrip(before, s.agyRecordedExecutables()...) }
	return s.configureAgentWith("agy", path, exe, apply, propose, strip)
}

func (s store) uninstallAgy() error {
	return s.uninstallAgentWith("agy", func(before []byte) ([]byte, error) {
		exes := s.agyRecordedExecutables()
		stripped, err := agyStrip(before, exes...)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(stripped, before) {
			// Nothing provably ours was removed. An interrupted upgrade may have
			// left an older generation the journal cannot name (or the journal may
			// predate the executable field): keep both the config and the recovery
			// journal instead of reporting a clean uninstall.
			if owned, err := agyContainsOwned(before, exes); err != nil || owned {
				return nil, errors.New("existing_shinphony_config")
			}
			return nil, errors.New("uninstall_ownership_ambiguous")
		}
		return stripped, nil
	})
}

// agyRecordedExecutables is the bounded ownership evidence from the journal:
// the current generation and, after an upgrade, the one it replaced. Callers
// hold the agent's install lock, so the record cannot change while it is used.
func (s store) agyRecordedExecutables() []string {
	rec, err := s.installRecord("agy")
	if err != nil {
		return nil
	}
	var out []string
	for _, exe := range []string{rec.Executable, rec.PreviousExecutable} {
		if exe != "" && !slices.Contains(out, exe) {
			out = append(out, exe)
		}
	}
	return out
}

// AgyHook is what the daemon needs from an Antigravity hook payload. Field
// names are camelCase protojson, and only fields the official contract
// documents are read; transcriptPath and other paths are never used.
type AgyHook struct {
	Event   string
	Session string
	Cwd     string
	Prompt  string
	Tool    string
	// ask_question: the question and its suggested answers.
	Questions []Question
	// ask_permission: Action and Target describe the request, Reason explains it.
	Action, Target, Reason string
	// Stop: fullyIdle true means every background task has finished.
	FullyIdle    bool
	HasFullyIdle bool
	Termination  string
	Error        string
	// Documented per-event identities. Absent on older payloads; nil means the
	// field was missing, which must stay distinguishable from zero.
	Invocation *int
	Steps      *int
	Step       *int
	Execution  *int
}

// ParseAgyHook reads one Antigravity hook payload. The event name is supplied
// by the installed command, never guessed from stdin.
func ParseAgyHook(event string, raw []byte) (AgyHook, bool) {
	if len(raw) > 262144 {
		return AgyHook{}, false
	}
	known := false
	for _, name := range agyEvents {
		if name == event {
			known = true
			break
		}
	}
	if !known {
		return AgyHook{}, false
	}
	var p struct {
		ConversationID string   `json:"conversationId"`
		WorkspacePaths []string `json:"workspacePaths"`
		LastUserInput  string   `json:"lastUserInput"`
		ToolCall       *struct {
			Name string          `json:"name"`
			Args json.RawMessage `json:"args"`
		} `json:"toolCall"`
		TerminationReason string `json:"terminationReason"`
		Error             string `json:"error"`
		FullyIdle         *bool  `json:"fullyIdle"`
		// Documented counters: invocationNum/initialNumSteps on invocations,
		// stepIdx on tool events, executionNum on Stop.
		InvocationNum   *int `json:"invocationNum"`
		InitialNumSteps *int `json:"initialNumSteps"`
		StepIdx         *int `json:"stepIdx"`
		ExecutionNum    *int `json:"executionNum"`
	}
	if json.Unmarshal(raw, &p) != nil || !agySessionID(p.ConversationID) {
		return AgyHook{}, false
	}
	h := AgyHook{Event: event, Session: p.ConversationID, Prompt: p.LastUserInput, Termination: p.TerminationReason, Error: p.Error}
	if len(p.WorkspacePaths) > 0 {
		h.Cwd = p.WorkspacePaths[0]
	}
	if p.FullyIdle != nil {
		h.HasFullyIdle, h.FullyIdle = true, *p.FullyIdle
	}
	// Negative counters are impossible on the documented wire; treat them as
	// absent so ordering decisions stay conservative instead of wrapping.
	h.Invocation, h.Steps = agyCounter(p.InvocationNum), agyCounter(p.InitialNumSteps)
	h.Step, h.Execution = agyCounter(p.StepIdx), agyCounter(p.ExecutionNum)
	if p.ToolCall != nil && p.ToolCall.Name != "" && len(p.ToolCall.Name) <= 64 {
		h.Tool = p.ToolCall.Name
		switch h.Tool {
		case "ask_question":
			h.Questions = parseQuestions(p.ToolCall.Args)
		case "ask_permission":
			var a struct {
				Action string `json:"Action"`
				Target string `json:"Target"`
				Reason string `json:"Reason"`
			}
			if json.Unmarshal(p.ToolCall.Args, &a) == nil {
				h.Action, h.Target, h.Reason = a.Action, a.Target, a.Reason
			}
		}
	}
	return h, true
}

func agyCounter(v *int) *int {
	if v == nil || *v < 0 || *v > 1_000_000_000 {
		return nil
	}
	n := *v
	return &n
}

// agySessionID accepts a bounded conversation UUID. It is hashed before it
// leaves the process, so only its shape is constrained here.
func agySessionID(s string) bool {
	if s == "" || len(s) > 512 {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}