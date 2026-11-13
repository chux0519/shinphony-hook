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
	r := newRelay()
	if m.Transport != nil {
		r.client.Transport = m.Transport
	}
	return (store{m.Directory}).pair(profile, lane, host, strings.TrimSpace(code), r)
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
