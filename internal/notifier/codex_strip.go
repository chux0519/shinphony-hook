package notifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

const codexManagedComment = "# Shinphony task notifications (managed; use uninstall to remove)"

// ownedDirs lists where our own notifier binaries live: the credentials
// directory, the directory of the binary being installed and of this process.
func (s store) ownedDirs(exe string) map[string]bool {
	dirs := map[string]bool{filepath.Clean(s.dir): true}
	if filepath.IsAbs(exe) {
		dirs[filepath.Dir(filepath.Clean(exe))] = true
	}
	if self, err := os.Executable(); err == nil {
		dirs[filepath.Dir(filepath.Clean(self))] = true
	}
	return dirs
}

// ownManaged reports whether argv is a notify entry we wrote, for any of our
// binaries (older releases included), and returns the callback it wraps.
func ownManaged(args []string, owned map[string]bool) (wrapped []string, ok bool) {
	if len(args) < 2 || !filepath.IsAbs(args[0]) || !owned[filepath.Dir(filepath.Clean(args[0]))] {
		return nil, false
	}
	switch {
	case len(args) == 2 && args[1] == "codex-notify-all":
		return nil, true
	case len(args) == 3 && args[1] == "codex-notify-chain":
		callback, err := DecodeComputerUseChain(args[2])
		return callback, err == nil
	}
	return nil, false
}

// stripCodexNotify removes only our notify entry from config.toml and keeps
// everything else byte for byte. Codex rewrites this file itself (model,
// project trust, status line), so those edits must never block setup. A notify
// entry we do not recognize is left alone; proposing then fails closed.
// outer reports that Computer Use had wrapped our entry.
func stripCodexNotify(current []byte, owned map[string]bool) (base []byte, outer bool, err error) {
	var doc map[string]any
	if toml.Unmarshal(current, &doc) != nil {
		return nil, false, errors.New("invalid_codex_config")
	}
	if _, present := doc["notify"]; !present {
		return current, false, nil
	}
	args, err := notifyArgs(current)
	if err != nil {
		return current, false, nil // not a string list: never ours
	}
	if len(args) == 4 && ComputerUseCommand(args[:2]) && args[2] == "--previous-notify" && len(args[3]) <= 16384 {
		var nested []string
		if json.Unmarshal([]byte(args[3]), &nested) != nil {
			return current, false, nil
		}
		callback, ok := ownManaged(nested, owned)
		if !ok || (callback != nil && !equalArgs(callback, args[:2])) {
			return current, false, nil
		}
		base, err = replaceNotify(current, args[:2])
		return base, true, err
	}
	callback, ok := ownManaged(args, owned)
	if !ok {
		return current, false, nil
	}
	if callback != nil {
		base, err = replaceNotify(current, callback)
		return base, false, err
	}
	base, err = removeNotify(current)
	return base, false, err
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// removeNotify deletes the top-level notify line we added, plus our marker
// comment directly above it and the blank line we put after it.
func removeNotify(before []byte) ([]byte, error) {
	var p unstable.Parser
	p.Reset(before)
	for p.NextExpression() {
		n := p.Expression()
		if n.Kind == unstable.Table || n.Kind == unstable.ArrayTable {
			break
		}
		if n.Kind != unstable.KeyValue {
			continue
		}
		key := n.Key()
		if !key.Next() || string(key.Node().Data) != "notify" {
			continue
		}
		k := key.Node().Raw
		if key.Next() {
			continue
		}
		start := int(k.Offset)
		for start > 0 && before[start-1] != '\n' {
			start--
		}
		// The value ends at the closing bracket; drop the rest of that line.
		end := start
		children := n.Value().Children()
		for children.Next() {
			r := children.Node().Raw
			end = int(r.Offset + r.Length)
		}
		close := bytes.IndexByte(before[end:], ']')
		if close < 0 {
			break
		}
		end += close + 1
		if nl := bytes.IndexByte(before[end:], '\n'); nl >= 0 {
			end += nl + 1
		} else {
			end = len(before)
		}
		comment := []byte(codexManagedComment + "\n")
		if start >= len(comment) && bytes.Equal(before[start-len(comment):start], comment) {
			start -= len(comment)
			if end < len(before) && before[end] == '\n' {
				end++
			}
		}
		result := append(append([]byte{}, before[:start]...), before[end:]...)
		var verify map[string]any
		if toml.Unmarshal(result, &verify) != nil {
			return nil, errors.New("invalid_codex_config")
		}
		if _, still := verify["notify"]; still {
			return nil, errors.New("unsupported_notify_format")
		}
		return result, nil
	}
	return nil, errors.New("unsupported_notify_format")
}

// remergeCodex re-installs our notify entry into a config.toml others edited.
// The journal's original becomes the current file without our entry, so a
// later uninstall restores exactly the user's latest settings. Re-running is
// idempotent, which covers a crash between the journal and config writes.
func (s store) remergeCodex(rec installRecord, path, exe string, before []byte, apply bool) error {
	base, outer, err := stripCodexNotify(before, s.ownedDirs(exe))
	if err != nil {
		return err
	}
	outer = outer || rec.ComputerUseOuter
	var desired []byte
	if outer {
		desired, err = proposedComputerUseOuter(base, exe)
		if err != nil {
			// Computer Use was removed since: fall back to a direct entry.
			outer = false
			desired, err = proposedCodex(base, exe)
		}
	} else {
		desired, err = proposedCodex(base, exe)
	}
	if err != nil || !apply {
		return err
	}
	oldRecord, err := readPrivate(s.recordPath("codex"))
	if err != nil {
		return err
	}
	rec = installRecord{Schema: 2, Path: path, Before: base, Existed: true, After: digest(desired), ComputerUseOuter: outer}
	updated, _ := json.Marshal(rec)
	if err = replaceConfig(s.recordPath("codex"), oldRecord, true, updated); err != nil {
		return err
	}
	if bytes.Equal(before, desired) {
		return nil
	}
	return replaceConfig(path, before, true, desired)
}
