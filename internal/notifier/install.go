package notifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// Keep original bytes, including comments. Add a top-level notify entry or
// chain the explicitly supported Computer Use callback; reject unknown hooks.
type installRecord struct {
	Schema           int    `json:"schema"`
	Path             string `json:"path"`
	Before           []byte `json:"before"`
	Existed          bool   `json:"existed"`
	After            string `json:"after"`
	PreviousAfter    string `json:"previousAfter,omitempty"`
	ComputerUseOuter bool   `json:"computerUseOuter,omitempty"`
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func configRead(path string) ([]byte, bool, error) {
	if e := checkConfigParents(filepath.Dir(path)); e != nil {
		return nil, false, e
	}
	st, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil, false, nil
	}
	if e != nil || !st.Mode().IsRegular() || st.Size() > 1048576 {
		return nil, false, errUnsafe
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, false, errConfig
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) {
		return nil, false, errUnsafe
	}
	b, e := io.ReadAll(io.LimitReader(f, 1048577))
	if e != nil || len(b) > 1048576 {
		return nil, false, errConfig
	}
	return b, true, nil
}

func codexConfigPath(home string) string {
	if dir := os.Getenv("CODEX_HOME"); dir != "" {
		return filepath.Join(dir, "config.toml")
	}
	return filepath.Join(home, ".codex", "config.toml")
}

func proposedCodex(before []byte, exe string) ([]byte, error) {
	var doc map[string]any
	if e := toml.Unmarshal(before, &doc); e != nil {
		return nil, errors.New("invalid_codex_config")
	}
	if existing, ok := doc["notify"]; ok {
		return chainComputerUse(before, exe, existing)
	}
	// Project trust paths/comments may contain our name. Only actual notify or
	// native hook configuration (checked below) can conflict with installation.
	head, e := toml.Marshal(map[string]any{"notify": []string{exe, "codex-notify-all"}})
	if e != nil {
		return nil, errConfig
	}
	result := append([]byte(codexManagedComment+"\n"), head...)
	result = append(result, '\n')
	result = append(result, before...)
	var verify map[string]any
	if toml.Unmarshal(result, &verify) != nil {
		return nil, errConfig
	}
	return result, nil
}

func (s store) recordPath(agent string) string { return filepath.Join(s.dir, agent+"-install.json") }
func (s store) installRecord(agent string) (installRecord, error) {
	var rec installRecord
	b, e := readPrivate(s.recordPath(agent))
	if e != nil {
		return rec, e
	}
	if json.Unmarshal(b, &rec) != nil || (rec.Schema != 1 && rec.Schema != 2) || !filepath.IsAbs(rec.Path) || len(rec.Before) > 1048576 {
		return rec, errConfig
	}
	return rec, nil
}

// A private, flushed backup precedes mutation. If interrupted, only either
// exact expected hash is accepted on the next invocation. User edits halt it.
func (s store) configureCodex(path, exe string, apply bool) error {
	// Native hooks merge with notify. Refuse an older Shinphony integration
	// rather than installing a second sender for the same events.
	if _, err := os.Stat(filepath.Dir(path)); err == nil {
		raw, _, e := configRead(filepath.Join(filepath.Dir(path), "hooks.json"))
		if e != nil {
			return e
		}
		// Our own native hooks (codex-hook-all) are expected there.
		if raw, e = codexHooks.strip(raw); e != nil {
			return e
		}
		if bytes.Contains(bytes.ToLower(raw), []byte("shinphony")) || bytes.Contains(raw, []byte("notify.py")) {
			return errors.New("existing_shinphony_config")
		}
	} else if !os.IsNotExist(err) {
		return errors.New("invalid_codex_config")
	}
	return s.configureAgent("codex", path, exe, apply, proposedCodex)
}

// Codex's native lifecycle hooks (hooks.json, stable and on by default since
// 0.16x). notify in config.toml stays for chaining Computer Use only.
var codexHooks = hookTarget{
	subcommand: "codex-hook-all",
	// PreToolUse only for the question tools: the question shows on the phone
	// the moment Codex asks it (request_user_input / request_user_input_async).
	matchers: map[string]string{"PostToolUse": "Bash", "PreToolUse": "^request_user_input"},
	events:   []string{"SessionStart", "UserPromptSubmit", "Stop", "PermissionRequest", "SessionEnd", "PostToolUse", "PreToolUse"},
	invalid:  "invalid_codex_config",
}

func codexHooksPath(home string) string {
	return filepath.Join(filepath.Dir(codexConfigPath(home)), "hooks.json")
}

func (s store) configureCodexHooks(path, exe string, apply bool) error {
	return s.configureAgentWith("codex-hooks", path, exe, apply, codexHooks.propose, codexHooks.strip)
}

func (s store) uninstallCodexHooks() error {
	if e := s.uninstallAgentWith("codex-hooks", codexHooks.strip); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}

func (s store) configureAgent(agent, path, exe string, apply bool, propose func([]byte, string) ([]byte, error)) error {
	return s.configureAgentWith(agent, path, exe, apply, propose, nil)
}

// stripFunc removes only our own entries from a config. Agents whose config
// other tools also rewrite (Claude Code saves settings.json itself; MemSpace
// adds hooks and patch rows) provide one, so an edited file is merged in place
// instead of refused. Propose functions for them strip before adding.
type stripFunc func([]byte) ([]byte, error)

func (s store) configureAgentWith(agent, path, exe string, apply bool, propose func([]byte, string) ([]byte, error), strip stripFunc) error {
	if !filepath.IsAbs(exe) || !filepath.IsAbs(path) {
		return errConfig
	}
	if e := s.initialize(); e != nil {
		return e
	}
	unlock, e := s.lock(agent + "-install")
	if e != nil {
		return e
	}
	defer unlock()
	if _, e := os.Lstat(filepath.Dir(path)); os.IsNotExist(e) {
		if !apply {
			return nil
		}
		if e := checkParents(filepath.Dir(filepath.Dir(path))); e != nil {
			return e
		}
		if e := makePrivateDir(filepath.Dir(path)); e != nil {
			return e
		}
	}
	before, existed, e := configRead(path)
	if e != nil {
		return e
	}
	rec, re := s.installRecord(agent)
	if re == nil {
		if rec.Path != path {
			return errors.New("codex_config_location_changed")
		}
		if agent == "codex" && rec.ComputerUseOuter {
			propose = proposedComputerUseOuter
		}
		if digest(before) == rec.After || (rec.Schema == 2 && rec.PreviousAfter != "" && digest(before) == rec.PreviousAfter) {
			desired, err := propose(rec.Before, exe)
			if err != nil {
				return err
			}
			if digest(before) == digest(desired) {
				return nil
			}
			if !apply {
				return nil
			}
			if digest(before) == rec.PreviousAfter && digest(desired) != rec.After {
				return errors.New("installer_version_changed")
			}
			if digest(before) == rec.After {
				oldRecord, err := readPrivate(s.recordPath(agent))
				if err != nil {
					return err
				}
				rec.Schema = 2
				rec.PreviousAfter = rec.After
				rec.After = digest(desired)
				updated, _ := json.Marshal(rec)
				if err = replaceConfig(s.recordPath(agent), oldRecord, true, updated); err != nil {
					return err
				}
			}
			return replaceConfig(path, before, existed, desired)
		}
		if digest(before) != digest(rec.Before) || existed != rec.Existed {
			if agent == "codex" && existed {
				updated, desired, err := adoptComputerUseOuter(before, rec, exe)
				if err != nil {
					// Codex rewrites config.toml itself; only our notify entry
					// matters. Unknown notify entries still fail closed there.
					return s.remergeCodex(rec, path, exe, before, apply)
				}
				if !apply {
					return nil
				}
				oldRecord, err := readPrivate(s.recordPath(agent))
				if err != nil {
					return err
				}
				raw, _ := json.Marshal(updated)
				// Journal both hashes before changing the file; interrupted writes
				// resume through the existing PreviousAfter recovery path.
				if err = replaceConfig(s.recordPath(agent), oldRecord, true, raw); err != nil {
					return err
				}
				return replaceConfig(path, before, true, desired)
			}
			if strip != nil {
				return s.remerge(agent, rec, path, exe, before, existed, apply, propose, strip)
			}
			return errors.New("codex_config_changed")
		}
		// Resume a journal written before config commit.
	} else if !os.IsNotExist(re) {
		return errors.New("invalid_install_record")
	}
	after, e := propose(before, exe)
	if e != nil {
		return e
	}
	if !apply {
		return nil
	}
	if re != nil {
		rec = installRecord{Schema: 1, Path: path, Before: before, Existed: existed, After: digest(after)}
		raw, _ := json.Marshal(rec)
		f, e := createPrivate(s.recordPath(agent))
		if e != nil {
			return e
		}
		_, e = f.Write(raw)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil || ce != nil {
			return errors.New("backup_failed")
		}
	} else if rec.After != digest(after) {
		return errors.New("installer_version_changed")
	}
	return replaceConfig(path, before, existed, after)
}

// remerge re-adds our entries to a file others edited since installation. The
// journal's original becomes that file without our entries, so a later exact
// restore keeps the other tools' changes.
func (s store) remerge(agent string, rec installRecord, path, exe string, before []byte, existed, apply bool, propose func([]byte, string) ([]byte, error), strip stripFunc) error {
	base, err := strip(before)
	if err != nil {
		return err
	}
	desired, err := propose(before, exe)
	if err != nil || !apply {
		return err
	}
	oldRecord, err := readPrivate(s.recordPath(agent))
	if err != nil {
		return err
	}
	rec = installRecord{Schema: 2, Path: path, Before: base, Existed: existed, After: digest(desired)}
	updated, _ := json.Marshal(rec)
	if err = replaceConfig(s.recordPath(agent), oldRecord, true, updated); err != nil {
		return err
	}
	if bytes.Equal(before, desired) {
		return nil
	}
	return replaceConfig(path, before, existed, desired)
}

func replaceConfig(path string, before []byte, existed bool, after []byte) error {
	tmp := filepath.Join(filepath.Dir(path), ".shinphony-"+randomID())
	f, e := createPrivate(tmp)
	if e != nil {
		return e
	}
	defer os.Remove(tmp)
	_, e = f.Write(after)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("config_write_failed")
	}
	current, present, e := configRead(path)
	if e != nil || present != existed || !bytes.Equal(current, before) {
		return errors.New("codex_config_changed")
	}
	return os.Rename(tmp, path)
}

func (s store) uninstallCodex() error {
	owned := s.ownedDirs("")
	return s.uninstallAgentWith("codex", func(current []byte) ([]byte, error) {
		base, _, err := stripCodexNotify(current, owned)
		return base, err
	})
}
func (s store) uninstallAgent(agent string) error { return s.uninstallAgentWith(agent, nil) }
func (s store) uninstallAgentWith(agent string, strip stripFunc) error {
	if e := s.initialize(); e != nil {
		return e
	}
	unlock, e := s.lock(agent + "-install")
	if e != nil {
		return e
	}
	defer unlock()
	rec, e := s.installRecord(agent)
	if e != nil {
		return e
	}
	current, exists, e := configRead(rec.Path)
	if e != nil {
		return e
	}
	if digest(current) == digest(rec.Before) && exists == rec.Existed {
		return os.Remove(s.recordPath(agent))
	}
	if exists && strip != nil && digest(current) != rec.After && !(rec.Schema == 2 && digest(current) == rec.PreviousAfter) {
		stripped, err := strip(current)
		if err != nil {
			return err
		}
		if !rec.Existed && len(bytes.TrimSpace(stripped)) == 0 {
			e = os.Remove(rec.Path)
		} else if !bytes.Equal(stripped, current) {
			e = replaceConfig(rec.Path, current, true, stripped)
		}
		if e != nil {
			return e
		}
		return os.Remove(s.recordPath(agent))
	}
	if !exists || (digest(current) != rec.After && !(rec.Schema == 2 && digest(current) == rec.PreviousAfter)) {
		return errors.New("codex_config_changed")
	}
	if rec.Existed {
		e = replaceConfig(rec.Path, current, true, rec.Before)
	} else {
		e = os.Remove(rec.Path)
	}
	if e != nil {
		return e
	}
	return os.Remove(s.recordPath(agent))
}
