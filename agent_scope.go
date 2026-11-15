package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"net.potafree/shinphony/hook/internal/notifier"
)

// supportedAgents is the install order and the order of the status rows.
var supportedAgents = []string{"codex", "claude", "dsh", "agy"}

// agentRefreshInterval bounds how often an update or a service start installs
// and refreshes agent integrations. Joining agents must not become a background
// scan that runs on every restart.
const agentRefreshInterval = time.Hour

// agentState is the private record of what setup was asked to support, plus
// what the last refresh of each agent did. It lives in the credentials
// directory next to the install records, with the same private-file rules.
type agentState struct {
	Schema    int                     `json:"schema"`
	Auto      bool                    `json:"auto"`
	Agents    []string                `json:"agents,omitempty"`
	Refreshed int64                   `json:"refreshed,omitempty"`
	Refused   map[string]agentRefusal `json:"refused,omitempty"`
	// Excluded holds agents the user uninstalled on purpose. The automatic join
	// must never add one back; only an explicit setup does.
	Excluded []string `json:"excluded,omitempty"`
}

// agentRefusal remembers why an agent was skipped. The hash of the config it
// was refused with means a later refresh retries only after the user or the
// agent changed that file, instead of every hour.
type agentRefusal struct {
	Code string `json:"code"`
	Hash string `json:"hash,omitempty"`
}

// agentRecord is one status row: installed, skipped with a reason, or neither.
type agentRecord struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

func (st agentState) scopeSet() bool { return st.Auto || len(st.Agents) > 0 }

func agentStatePath(dir string) string { return filepath.Join(dir, "agents.json") }

func loadAgentState(dir string) (agentState, bool, error) {
	st := agentState{Schema: 1}
	path := agentStatePath(dir)
	if err := privatePath(path, false); os.IsNotExist(err) {
		return st, false, nil
	} else if err != nil {
		return agentState{}, false, err
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 65536 {
		return agentState{}, false, errors.New("invalid_agent_state")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&st) != nil || d.Decode(new(any)) != io.EOF || st.Schema != 1 {
		return agentState{}, false, errors.New("invalid_agent_state")
	}
	for _, agent := range st.Agents {
		if !slices.Contains(supportedAgents, agent) {
			return agentState{}, false, errors.New("invalid_agent_state")
		}
	}
	for _, agent := range st.Excluded {
		if !slices.Contains(supportedAgents, agent) {
			return agentState{}, false, errors.New("invalid_agent_state")
		}
	}
	return st, true, nil
}

// saveAgentState replaces the record atomically; the temporary file is created
// private, so a crash never leaves a readable or half-written scope behind.
func saveAgentState(dir string, st agentState) error {
	st.Schema = 1
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	// The credentials directory always exists here: setup and pairing created it
	// through the notifier's own private checks. Never create it from here, and
	// never walk its ancestors (a caller's temp path may contain /var).
	if err = privatePath(dir, true); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".agents-"+randomEventSeed())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = privatePath(tmp, false); err != nil {
		return err
	}
	return os.Rename(tmp, agentStatePath(dir))
}

// migrateAgentScopeOnce treats an existing install without a scope record as
// "auto", the App default that predates the record. The caller records it once;
// a user who never paired an agent gets nothing.
func migrateAgentScopeOnce(m notifier.Manager) (bool, error) {
	st, _, err := loadAgentState(m.Directory)
	if err != nil || st.scopeSet() {
		return false, err
	}
	// An install record can only exist once setup created the directory; asking
	// InstalledAgents about a missing one is an unsafe path, not an empty answer.
	if _, err = os.Lstat(m.Directory); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	installed, err := m.InstalledAgents()
	if err != nil || len(installed) == 0 {
		return false, err
	}
	st.Auto, st.Agents = true, nil
	return true, saveAgentState(m.Directory, st)
}

// recordSetupScope stores what the user asked setup to support. "auto" covers
// every agent detected later; a single agent only adds to an explicit list and
// never shrinks an existing auto scope.
func recordSetupScope(m notifier.Manager, requested string) error {
	if requested != "auto" && !slices.Contains(supportedAgents, requested) {
		return errors.New("invalid_agent_scope")
	}
	st, _, err := loadAgentState(m.Directory)
	if err != nil {
		return err
	}
	if requested == "auto" {
		st.Auto, st.Agents, st.Excluded = true, nil, nil
	} else {
		// A single agent the user sets up again is an explicit request, so a
		// recorded removal no longer applies to it. The scope itself only adds
		// to an explicit list and never shrinks an existing auto scope.
		st.Excluded = slices.DeleteFunc(st.Excluded, func(agent string) bool { return agent == requested })
		if !st.Auto && !slices.Contains(st.Agents, requested) {
			st.Agents = append(st.Agents, requested)
		}
	}
	return saveAgentState(m.Directory, st)
}

// recordAgentUninstall remembers the user's explicit removal: the automatic join
// skips the agent until a setup asks for it again. A refusal recorded earlier
// for that agent no longer says anything.
func recordAgentUninstall(m notifier.Manager, agent string) error {
	if !slices.Contains(supportedAgents, agent) {
		return errors.New("invalid_agent_scope")
	}
	st, _, err := loadAgentState(m.Directory)
	if err != nil {
		return err
	}
	if !slices.Contains(st.Excluded, agent) {
		st.Excluded = append(st.Excluded, agent)
	}
	delete(st.Refused, agent)
	return saveAgentState(m.Directory, st)
}

// configureAgent is the seam tests use to prove a refused agent is not retried
// while its config is unchanged.
var configureAgent = func(m notifier.Manager, agent, exe string, apply bool) error {
	return m.Configure(agent, exe, apply)
}

func agentErrorCode(err error) string {
	if err != nil && identifier.MatchString(err.Error()) {
		return err.Error()
	}
	return "agent_configure_failed"
}

// agentConfigHash fingerprints the files a refusal was based on.
func agentConfigHash(m notifier.Manager, agent string) string {
	paths, err := m.AgentConfigPaths(agent)
	if err != nil || len(paths) == 0 {
		return ""
	}
	h := sha256.New()
	for _, path := range paths {
		h.Write([]byte(path))
		if raw, err := os.ReadFile(path); err == nil {
			h.Write([]byte{'1'})
			h.Write(raw)
		} else {
			h.Write([]byte{'0'})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// refreshLockName is the private lock file that serialises refreshes across
// processes: the update path and a service start can otherwise write the same
// agent config and scope record at the same time.
const refreshLockName = ".refresh.lock"

// refreshLockWait bounds how long a second caller waits for the holder. The work
// is local file I/O, so waiting briefly is enough; a caller that still finds the
// lock busy leaves the work to the holder instead of duplicating it.
var refreshLockWait = 2 * time.Second

var errRefreshBusy = errors.New("refresh_busy")

func refreshLock(dir string) (func(), error) {
	path := filepath.Join(dir, refreshLockName)
	deadline := time.Now().Add(refreshLockWait)
	for {
		unlock, err := lockFilePath(path)
		if err == nil {
			return unlock, nil
		}
		if !errors.Is(err, errRefreshBusy) || !time.Now().Before(deadline) {
			return nil, err
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// refreshMode says which half of the work a caller owns: the update path
// refreshes installed agents and joins new ones, while a service start only
// joins agents detected since setup.
type refreshMode int

const (
	refreshInstalledAndJoin refreshMode = iota
	refreshJoinOnly
)

// refreshIntegrationsAt refreshes what setup installed and, when the scope is
// "auto", joins agents detected since then with the same check-then-apply rules
// as setup. A refusal on a newly detected agent is remembered, not an error;
// only an already installed agent that cannot be refreshed fails, so the update
// path keeps today's meaning. now is a parameter so the hourly join limit is
// testable.
func refreshIntegrationsAt(m notifier.Manager, exe string, now time.Time) ([]agentRecord, error) {
	return refreshAgents(m, exe, now, refreshInstalledAndJoin)
}

// joinDetectedAgentsAt is the service-start half: it joins agents detected since
// setup (at most hourly) and never reconfigures an installed agent, so a restart
// cannot rewrite a config the user already has.
func joinDetectedAgentsAt(m notifier.Manager, exe string, now time.Time) ([]agentRecord, error) {
	return refreshAgents(m, exe, now, refreshJoinOnly)
}

func refreshAgents(m notifier.Manager, exe string, now time.Time, mode refreshMode) ([]agentRecord, error) {
	if _, err := os.Lstat(m.Directory); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	// What is installed and what is due must be decided while holding the lock:
	// another process may be changing the same files right now.
	unlock, err := refreshLock(m.Directory)
	if errors.Is(err, errRefreshBusy) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, _, err := loadAgentState(m.Directory)
	if err != nil {
		return nil, err
	}
	installed, err := m.InstalledAgents()
	if err != nil {
		return nil, err
	}
	dirty := false
	if !st.scopeSet() {
		if len(installed) == 0 {
			// Never paired an agent: there is no scope to remember and nothing
			// to join.
			return nil, nil
		}
		st.Auto, st.Agents = true, nil
		dirty = true
	}
	// Installed agents refresh on every update, as before, so their hooks follow
	// the new executable. Only joining agents detected since setup is limited to
	// once an hour; that is the part that would otherwise scan on every start.
	due := st.Refreshed == 0 || now.Unix() >= st.Refreshed+int64(agentRefreshInterval/time.Second)
	records := make([]agentRecord, 0, len(supportedAgents))
	failures := make([]string, 0, len(installed))
	if mode == refreshInstalledAndJoin {
		for _, agent := range installed {
			record := agentRecord{ID: agent, State: "installed"}
			err := configureAgent(m, agent, exe, true)
			if err == nil && agent == "codex" {
				err = installTaskSkill(exe)
			}
			if err != nil {
				record.Reason = agentErrorCode(err)
				failures = append(failures, agent+":"+record.Reason)
			}
			if _, ok := st.Refused[agent]; ok {
				delete(st.Refused, agent)
				dirty = true
			}
			records = append(records, record)
		}
	}
	if st.Auto && due {
		detected, e := m.DetectedAgents()
		if e != nil {
			return records, e
		}
		for _, agent := range detected {
			if slices.Contains(installed, agent) || slices.Contains(st.Excluded, agent) {
				// An agent the user uninstalled on purpose stays removed; only a
				// setup asks for it again.
				continue
			}
			hash := agentConfigHash(m, agent)
			if refused, ok := st.Refused[agent]; ok && hash != "" && refused.Hash == hash {
				records = append(records, agentRecord{ID: agent, State: "skipped", Reason: refused.Code})
				continue
			}
			err = configureAgent(m, agent, exe, false)
			if err == nil {
				if err = configureAgent(m, agent, exe, true); err == nil && agent == "codex" {
					err = installTaskSkill(exe)
				}
			}
			if err != nil {
				// The user disabled a group or edited a config: skip this agent
				// and keep the others, exactly like setup would refuse it.
				code := agentErrorCode(err)
				if st.Refused == nil {
					st.Refused = map[string]agentRefusal{}
				}
				st.Refused[agent] = agentRefusal{Code: code, Hash: hash}
				dirty = true
				records = append(records, agentRecord{ID: agent, State: "skipped", Reason: code})
				continue
			}
			if _, ok := st.Refused[agent]; ok {
				delete(st.Refused, agent)
			}
			dirty = true
			records = append(records, agentRecord{ID: agent, State: "installed"})
		}
		st.Refreshed = now.Unix()
		dirty = true
	}
	if dirty {
		if err = saveAgentState(m.Directory, st); err != nil {
			return records, err
		}
	}
	if len(failures) > 0 {
		return records, errors.New("integration_refresh_failed: " + strings.Join(failures, ","))
	}
	return records, nil
}

// agentRecords reports one row per supported agent for status. It only reads:
// the App must not trigger installs by polling.
func agentRecords(m notifier.Manager) ([]agentRecord, error) {
	if _, err := os.Lstat(m.Directory); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	st, _, err := loadAgentState(m.Directory)
	if err != nil {
		return nil, err
	}
	installed, err := m.InstalledAgents()
	if err != nil {
		return nil, err
	}
	records := make([]agentRecord, 0, len(supportedAgents))
	for _, agent := range supportedAgents {
		switch {
		case slices.Contains(installed, agent):
			records = append(records, agentRecord{ID: agent, State: "installed"})
		case slices.Contains(st.Excluded, agent):
			// Removed on purpose: nothing to do, nothing to show.
			records = append(records, agentRecord{ID: agent, State: "not_detected"})
		case st.Refused[agent].Code != "":
			records = append(records, agentRecord{ID: agent, State: "skipped", Reason: st.Refused[agent].Code})
		default:
			records = append(records, agentRecord{ID: agent, State: "not_detected"})
		}
	}
	return records, nil
}
