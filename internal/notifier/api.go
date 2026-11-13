package notifier

import (
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (m Manager) ValidateReset(profile, lane, host string) error {
	s := store{m.Directory}
	p, err := s.path(profile)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(p); os.IsNotExist(err) {
		return nil
	}
	c, err := s.load(profile)
	if err != nil || c.Lane != lane || c.Host != host {
		return errConfig
	}
	return nil
}

// Only called after the owner has revoked this destination at the relay.
func (m Manager) Reset(profile string) error {
	s := store{m.Directory}
	if err := s.initialize(); err != nil {
		return err
	}
	p, err := s.path(profile)
	if err != nil {
		return err
	}
	lock := filepath.Join(s.dir, profile+".lock")
	if info, e := os.Lstat(lock); e == nil {
		if e = checkPrivate(lock, false); e != nil {
			return e
		}
		if time.Since(info.ModTime()) < 30*time.Second {
			return errors.New("busy_or_interrupted_install")
		}
		if e = os.Remove(lock); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	unlock, err := s.lock(profile)
	if err != nil {
		return err
	}
	defer unlock()
	for _, path := range []string{p, filepath.Join(s.dir, profile+".pending")} {
		if _, err = os.Lstat(path); os.IsNotExist(err) {
			continue
		}
		if err = checkPrivate(path, false); err != nil {
			return err
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

// Public boundary of the migrated, transactional notifier. Credentials and
// original config bytes stay within this package and are never returned.
type Manager struct {
	Directory string
	Transport http.RoundTripper
}

// Detect only supported CLIs or their existing per-user configuration. Do not
// install agents or create unused agent directories during automatic setup.
func (m Manager) DetectedAgents() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	var agents []string
	for _, entry := range []struct{ name, command, path string }{
		{"codex", "codex", filepath.Dir(codexConfigPath(home))},
		{"claude", "claude", filepath.Dir(claudeConfigPath(home))},
		{"dsh", "dsh", dshHome(home)},
	} {
		_, cliErr := exec.LookPath(entry.command)
		info, statErr := os.Stat(entry.path)
		if cliErr == nil || (statErr == nil && info.IsDir()) {
			agents = append(agents, entry.name)
		}
	}
	return agents, nil
}

// Only refresh integrations already installed by this user; never enable a new
// agent integration as a side effect of a background binary update.
func (m Manager) InstalledAgents() ([]string, error) {
	var agents []string
	for _, agent := range []string{"codex", "claude", "dsh"} {
		_, err := (store{m.Directory}).installRecord(agent)
		if err == nil {
			agents = append(agents, agent)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return agents, nil
}

func (m Manager) Pair(profile, lane, host, code string) error {
	return m.PairE2E(profile, lane, host, code, nil, false)
}

// PairE2E pairs with the phone's notification key and the Live Activity choice.
// A nil key keeps the plain path, as an older App does; `lines` asks for the
// Live Activity to keep today's plaintext lines.
func (m Manager) PairE2E(profile, lane, host, code string, key *E2EKey, lines bool) error {
	if key != nil && !key.valid() {
		return errConfig
	}
	r := newRelay()
	if m.Transport != nil {
		r.client.Transport = m.Transport
	}
	return (store{m.Directory}).pair(profile, lane, host, strings.TrimSpace(code), key, lines, r)
}

// PairingSettings is the optional part of the pairing input. Everything in it
// applies to an existing pairing as an update: `e2e` sets or rotates the phone's
// key, `E2E: null` removes it (back to plaintext), and `liveActivityLines`
// changes the Live Activity choice. A zero value changes nothing.
type PairingSettings struct {
	E2E               *E2EKey
	RemoveE2E         bool
	LiveActivityLines *bool
}

func (s PairingSettings) Empty() bool {
	return s.E2E == nil && !s.RemoveE2E && s.LiveActivityLines == nil
}

// UpdatePairing changes an existing pairing's notification settings without a
// new pairing code. The pairing itself (host, token, lane) is never changed:
// a mismatch is an error, not a re-pointing.
func (m Manager) UpdatePairing(profile, lane, host string, s PairingSettings) error {
	if s.Empty() || (s.E2E != nil && (!s.E2E.valid() || s.RemoveE2E)) {
		return errConfig
	}
	if !identifier.MatchString(profile) || !identifier.MatchString(host) {
		return errConfig
	}
	if _, err := lanePrefix(lane); err != nil {
		return err
	}
	return (store{m.Directory}).update(profile, func(c *credential) error {
		if c.Lane != lane || c.Host != host {
			return errConfig
		}
		switch {
		case s.RemoveE2E:
			c.E2E = nil
		case s.E2E != nil:
			c.E2E = s.E2E
		}
		if s.LiveActivityLines != nil {
			c.LiveActivityLines = *s.LiveActivityLines
		}
		return nil
	})
}

// SetLiveActivityLines changes the Live Activity choice of an existing pairing
// without re-pairing. The pairing itself (host, token, key) is untouched.
func (m Manager) SetLiveActivityLines(profile string, lines bool) error {
	return (store{m.Directory}).update(profile, func(c *credential) error {
		c.LiveActivityLines = lines
		return nil
	})
}

// LiveActivityLines reports the stored choice and whether the pairing is private.
func (m Manager) LiveActivityLines(profile string) (lines, private bool, err error) {
	c, err := (store{m.Directory}).load(profile)
	if err != nil {
		return false, false, err
	}
	return c.LiveActivityLines, c.E2E != nil, nil
}
func (m Manager) Paired(profile, lane, host string) (bool, error) {
	if !identifier.MatchString(profile) || !identifier.MatchString(host) {
		return false, errConfig
	}
	if _, err := lanePrefix(lane); err != nil {
		return false, err
	}
	s := store{m.Directory}
	if err := s.initialize(); err != nil {
		return false, err
	}
	c, err := s.load(profile)
	if err == nil {
		if c.Host != host || c.Lane != lane {
			return false, errConfig
		}
		return true, nil
	}
	p, _ := s.path(profile)
	if _, err = os.Lstat(p); !os.IsNotExist(err) {
		return false, errConfig
	}
	if _, err = os.Lstat(filepath.Join(s.dir, profile+".pending")); !os.IsNotExist(err) {
		return false, errors.New("pairing_needs_reconciliation")
	}
	return false, nil
}
func (m Manager) Configure(agent, exe string, apply bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return errConfig
	}
	s := store{m.Directory}
	switch agent {
	case "codex":
		if err = s.configureCodex(codexConfigPath(home), exe, apply); err != nil {
			return err
		}
		return s.configureCodexHooks(codexHooksPath(home), exe, apply)
	case "claude":
		return s.configureAgentWith(agent, claudeConfigPath(home), exe, apply, proposedClaude, stripClaude)
	case "dsh":
		return s.configureDSH(dshConfigPath(home), exe, apply)
	}
	return errConfig
}

// ConfigureCodexLifecycle merges only native lifecycle hooks. It deliberately
// leaves config.toml/notify untouched, including another tool's callback chain.
// Trust remains a separate, explicit user-approved operation.
func (m Manager) ConfigureCodexLifecycle(exe string, apply bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return errConfig
	}
	return (store{m.Directory}).configureCodexHooks(codexHooksPath(home), exe, apply)
}

func (m Manager) Uninstall(agent string) error {
	switch agent {
	case "codex":
		if err := (store{m.Directory}).uninstallCodexHooks(); err != nil {
			return err
		}
		return (store{m.Directory}).uninstallAgent(agent)
	case "claude":
		return (store{m.Directory}).uninstallAgentWith(agent, stripClaude)
	case "dsh":
		return (store{m.Directory}).uninstallDSH()
	}
	return errConfig
}
func (m Manager) Profiles() ([]string, error) {
	if err := checkPrivate(m.Directory, true); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(m.Directory)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if _, err := (store{m.Directory}).load(id); err == nil {
			out = append(out, id)
		}
		if len(out) > 100 {
			return nil, errors.New("too_many_pairings")
		}
	}
	return out, nil
}
func Extract(kind string, raw []byte) (id, status string, ok bool) {
	var e event
	switch kind {
	case "codex-notify-all":
		// Legacy Codex notify reports every turn, not completion of user work.
		return "", "", false
	case "claude-hook-all", "dsh-hook-all":
		// The DSH bridge sends Claude Code payloads (Stop only).
		e, ok = claudeEvent(raw)
	}
	return e.ID, e.Status, ok
}
