package notifier

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

// Deliberately narrow: this release only chains the known Computer Use callback.
// Arbitrary existing commands and shell wrappers still require explicit migration.
func ComputerUseCommand(args []string) bool {
	return len(args) == 2 && filepath.IsAbs(args[0]) && strings.HasSuffix(filepath.ToSlash(args[0]), "/Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient") && args[1] == "turn-ended"
}

func DecodeComputerUseChain(encoded string) ([]string, error) {
	if len(encoded) > 16384 {
		return nil, errors.New("invalid_chain")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	var args []string
	if err != nil || json.Unmarshal(raw, &args) != nil || !ComputerUseCommand(args) {
		return nil, errors.New("invalid_chain")
	}
	return args, nil
}

func chainComputerUse(before []byte, exe string, value any) ([]byte, error) {
	list, ok := value.([]any)
	if !ok {
		return nil, errors.New("existing_codex_notify")
	}
	args := []string{}
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("existing_codex_notify")
		}
		args = append(args, s)
	}
	if !ComputerUseCommand(args) {
		return nil, errors.New("existing_codex_notify")
	}
	raw, _ := json.Marshal(args)
	return replaceNotify(before, []string{exe, "codex-notify-chain", base64.RawURLEncoding.EncodeToString(raw)})
}

func replaceNotify(before []byte, args []string) ([]byte, error) {
	replacement, err := toml.Marshal(map[string]any{"notify": args})
	if err != nil {
		return nil, err
	}
	replacement = bytes.TrimSpace(bytes.SplitN(replacement, []byte("="), 2)[1])
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
		start := int(k.Offset + k.Length)
		eq := bytes.IndexByte(before[start:], '=')
		if eq < 0 {
			break
		}
		start += eq + 1
		for start < len(before) && (before[start] == ' ' || before[start] == '\t') {
			start++
		}
		if start >= len(before) || before[start] != '[' {
			break
		}
		children := n.Value().Children()
		end := start
		for children.Next() {
			r := children.Node().Raw
			end = int(r.Offset + r.Length)
		}
		for end < len(before) {
			c := before[end]
			if c == ']' {
				result := append([]byte{}, before[:start]...)
				result = append(result, replacement...)
				result = append(result, before[end+1:]...)
				var verify map[string]any
				if toml.Unmarshal(result, &verify) != nil {
					return nil, errors.New("invalid_codex_config")
				}
				return result, nil
			}
			if c == '#' {
				for end < len(before) && before[end] != '\n' {
					end++
				}
				continue
			}
			if c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != ',' {
				break
			}
			end++
		}
		break
	}
	return nil, errors.New("unsupported_notify_format")
}

func notifyArgs(raw []byte) ([]string, error) {
	var doc struct{ Notify []string }
	err := toml.Unmarshal(raw, &doc)
	return doc.Notify, err
}

// Keep Computer Use outermost so its own installer need not wrap us again.
// Its previous-notify argument is JSON argv, never a shell command.
func proposedComputerUseOuter(before []byte, exe string) ([]byte, error) {
	args, err := notifyArgs(before)
	if err != nil || !ComputerUseCommand(args) {
		return nil, errors.New("existing_codex_notify")
	}
	previous, _ := json.Marshal([]string{exe, "codex-notify-all"})
	return replaceNotify(before, append(args, "--previous-notify", string(previous)))
}

func recordedCodex(rec installRecord, exe string) ([]byte, error) {
	if rec.ComputerUseOuter {
		return proposedComputerUseOuter(rec.Before, exe)
	}
	return proposedCodex(rec.Before, exe)
}

// Recognize only a known Computer Use wrapper around the exact managed argv
// proven by our private installation journal. Unknown hooks and unrelated
// semantic edits still fail closed. Preserve current formatting outside notify.
func adoptComputerUseOuter(current []byte, rec installRecord, exe string) (installRecord, []byte, error) {
	fail := errors.New("codex_config_changed")
	args, err := notifyArgs(current)
	if err != nil || len(args) != 4 || !ComputerUseCommand(args[:2]) || args[2] != "--previous-notify" || len(args[3]) > 16384 {
		return rec, nil, fail
	}
	var nested []string
	if json.Unmarshal([]byte(args[3]), &nested) != nil || len(nested) < 2 || !filepath.IsAbs(nested[0]) {
		return rec, nil, fail
	}
	expected, err := recordedCodex(rec, nested[0])
	if err != nil || digest(expected) != rec.After {
		return rec, nil, fail
	}
	managed, err := notifyArgs(expected)
	if err != nil || !reflect.DeepEqual(managed, nested) {
		return rec, nil, fail
	}
	// A chain may already contain Computer Use. Flatten only the same callback,
	// otherwise preserving both without duplication would be ambiguous.
	if len(nested) == 3 && nested[1] == "codex-notify-chain" {
		callback, e := DecodeComputerUseChain(nested[2])
		if e != nil || !reflect.DeepEqual(callback, args[:2]) {
			return rec, nil, fail
		}
	} else if len(nested) != 2 || nested[1] != "codex-notify-all" {
		return rec, nil, fail
	}
	var a, b map[string]any
	if toml.Unmarshal(current, &a) != nil || toml.Unmarshal(expected, &b) != nil {
		return rec, nil, fail
	}
	delete(a, "notify")
	delete(b, "notify")
	if !reflect.DeepEqual(a, b) {
		return rec, nil, fail
	}
	base, err := replaceNotify(current, args[:2])
	if err != nil {
		return rec, nil, err
	}
	desired, err := proposedComputerUseOuter(base, exe)
	if err != nil {
		return rec, nil, err
	}
	rec.Schema = 2
	rec.Before, rec.Existed = base, true
	rec.ComputerUseOuter = true
	rec.PreviousAfter, rec.After = digest(current), digest(desired)
	return rec, desired, nil
}
