package notifier

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// DSH (DeepSeek Harness) has no hooks of its own. Its bridge plugin runs a
// Claude Code-format hooks file: SessionStart, UserPromptSubmit and Stop
// (no Notification/SessionEnd), so it reports work/reply state, not attention.
// The bridge row goes into the home-level cordis.patch.yml, which applies to
// every profile; the hooks file it points at is ours, beside the pairings.
const (
	dshBlockBegin   = "# >>> shinphony: task notifications (managed; use uninstall to remove)"
	dshBlockEnd     = "# <<< shinphony"
	dshHooksPackage = "@deepseek-ai/dsh-hooks-claude-code"
)

// dshHome follows DSH: $DSH_HOME, else the DSH_HOME a `dsh` launcher script
// exports (installs outside ~/.dsh write one), else ~/.dsh. The daemon's PATH
// may lack the user's bin directories, so common launcher locations are
// checked as well.
func dshHome(home string) string {
	if dir := os.Getenv("DSH_HOME"); dir != "" {
		return dir
	}
	candidates := []string{}
	if p, err := exec.LookPath("dsh"); err == nil {
		candidates = append(candidates, p)
	}
	for _, name := range []string{"dsh", "dsh.cmd", "dsh.ps1"} {
		candidates = append(candidates, filepath.Join(home, ".local", "bin", name), filepath.Join(home, "bin", name))
	}
	for _, p := range candidates {
		if dir := homeFromLauncher(p); dir != "" && filepath.IsAbs(dir) {
			return dir
		}
	}
	return filepath.Join(home, ".dsh")
}

var launcherHomeRE = regexp.MustCompile(`(?mi)^\s*(?:export\s+|set\s+|\$env:)?"?DSH_HOME"?\s*=\s*["']?([^"'\r\n]+?)["']?\s*$`)

// homeFromLauncher reads DSH_HOME from a small sh, cmd or PowerShell launcher.
// It never executes the script.
func homeFromLauncher(path string) string {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() >= 64<<10 {
		return ""
	}
	b, err := os.ReadFile(path)
	ext := strings.ToLower(filepath.Ext(path))
	if err != nil || !(bytes.HasPrefix(b, []byte("#!")) || ext == ".cmd" || ext == ".bat" || ext == ".ps1") {
		return ""
	}
	m := launcherHomeRE.FindSubmatch(b)
	if m == nil || bytes.ContainsAny(m[1], "$%`") {
		return ""
	}
	return filepath.Clean(string(m[1]))
}

func dshConfigPath(home string) string { return filepath.Join(dshHome(home), "cordis.patch.yml") }

func (s store) dshHooksPath() string { return filepath.Join(s.dir, "dsh-hooks.json") }

// dshHooks is the hooks file the bridge loads. DSH runs hook commands with
// PowerShell on Windows and bash elsewhere.
func dshHooks(exe string) []byte {
	command := "'" + strings.ReplaceAll(exe, "'", "'\\''") + "' dsh-hook-all"
	if runtime.GOOS == "windows" {
		command = "& '" + strings.ReplaceAll(exe, "'", "''") + "' dsh-hook-all"
	}
	handler := map[string]any{"type": "command", "command": command, "timeout": 6}
	// The bridge has no Notification or SessionEnd; it runs these three.
	group := []any{map[string]any{"hooks": []any{handler}}}
	doc := map[string]any{"hooks": map[string]any{"SessionStart": group, "UserPromptSubmit": group, "Stop": group}}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return append(b, '\n')
}

// proposedDSH appends the managed bridge row to the patch list. The patch file
// is a YAML list; an empty one (`[]`, comments) is replaced and a non-empty
// flow list is refused rather than rewritten.
func proposedDSH(hooksPath string) func([]byte, string) ([]byte, error) {
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	block := dshBlockBegin + "\n" +
		"- insert:\n" +
		"    - id: shinphony-notify\n" +
		"      name: " + q(dshHooksPackage) + "\n" +
		"      config:\n" +
		"        configPath: " + q(hooksPath) + "\n" +
		dshBlockEnd + "\n"
	return func(before []byte, _ string) ([]byte, error) {
		// Rows apply in order: an up-to-date block stays where it is.
		if bytes.Count(before, []byte(dshBlockBegin)) == 1 && bytes.Contains(before, []byte(block)) && patchEntries(before) == "block" {
			return before, nil
		}
		before = stripDSH(before)
		if bytes.Contains(bytes.ToLower(before), []byte("# >>> shinphony")) {
			return nil, errors.New("existing_shinphony_config")
		}
		text := before
		switch patchEntries(before) {
		case "empty":
			text = emptyListRE.ReplaceAll(before, nil)
		case "flow":
			return nil, errors.New("unsupported_dsh_patch_format")
		}
		if len(text) > 0 && text[len(text)-1] != '\n' {
			text = append(append([]byte{}, text...), '\n')
		}
		return append(append([]byte{}, text...), block...), nil
	}
}

// stripDSH removes our marked block, leaving everything else byte for byte.
func stripDSH(b []byte) []byte {
	i := bytes.Index(b, []byte(dshBlockBegin))
	if i < 0 {
		return b
	}
	j := bytes.Index(b[i:], []byte(dshBlockEnd))
	if j < 0 {
		return b
	}
	end := i + j + len(dshBlockEnd)
	if end < len(b) && b[end] == '\n' {
		end++
	}
	return append(append([]byte{}, b[:i]...), b[end:]...)
}

// stripDSHForUninstall keeps the file loadable: DSH refuses a patch file
// without entries, so one left with only comments gets `[]`.
func stripDSHForUninstall(b []byte) ([]byte, error) {
	out := stripDSH(b)
	if len(bytes.TrimSpace(out)) > 0 && patchEntries(out) == "empty" && !emptyListRE.Match(out) {
		out = append(out, "[]\n"...)
	}
	return out, nil
}

var emptyListRE = regexp.MustCompile(`(?m)^\[\]\s*$\n?`)

// patchEntries classifies a patch file as "empty" (only comments, blank lines
// or `[]`), "flow" (a non-empty `[...]` list) or "block".
func patchEntries(b []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case l == "" || strings.HasPrefix(l, "#") || l == "[]":
		case strings.HasPrefix(l, "["):
			return "flow"
		default:
			return "block"
		}
	}
	return "empty"
}

// configureDSH writes the hooks file before the patch row that loads it, so
// DSH never boots with a row pointing at a missing file. Rewriting the hooks
// file also moves the hook to a new immutable executable on upgrade.
func (s store) configureDSH(path, exe string, apply bool) error {
	if !filepath.IsAbs(exe) {
		return errConfig
	}
	if apply {
		if e := s.initialize(); e != nil {
			return e
		}
		if e := writePrivate(s.dshHooksPath(), dshHooks(exe)); e != nil {
			return e
		}
	}
	strip := func(b []byte) ([]byte, error) { return stripDSH(b), nil }
	return s.configureAgentWith("dsh", path, exe, apply, proposedDSH(s.dshHooksPath()), strip)
}

func (s store) uninstallDSH() error {
	if e := s.uninstallAgentWith("dsh", stripDSHForUninstall); e != nil {
		return e
	}
	if e := os.Remove(s.dshHooksPath()); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}

func writePrivate(path string, data []byte) error {
	tmp := path + "." + randomID() + ".tmp"
	f, e := createPrivate(tmp)
	if e != nil {
		return e
	}
	defer os.Remove(tmp)
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e != nil || ce != nil {
		return errors.New("config_write_failed")
	}
	return os.Rename(tmp, path)
}
