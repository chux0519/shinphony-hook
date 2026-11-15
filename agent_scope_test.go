package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net.potafree/shinphony/hook/internal/notifier"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// agentTestHome builds a hermetic home: no real agent CLI is reachable, every
// agent config path points inside the temporary home, and the credentials
// directory is a fresh private directory.
func agentTestHome(t *testing.T) (string, string, string, notifier.Manager) {
	t.Helper()
	home := privateTemp(t)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	bin := filepath.Join(home, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("CODEX_HOME", filepath.Join(home, "codex"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "claude"))
	t.Setenv("DSH_HOME", filepath.Join(home, "dsh"))
	creds := filepath.Join(home, "credentials")
	exe := filepath.Join(home, managedPrefix+strings.Repeat("a", 64))
	return home, creds, exe, notifier.Manager{Directory: creds}
}

// installTestAgent reproduces what a setup leaves behind before this
// iteration: install records and agent configs, but no scope record.
func installTestAgent(t *testing.T, m notifier.Manager, exe, agent string) {
	t.Helper()
	if err := m.Configure(agent, exe, true); err != nil {
		t.Fatal(err)
	}
	if agent == "codex" {
		if err := installTaskSkill(exe); err != nil {
			t.Fatal(err)
		}
	}
}

// detectTestAgy makes Antigravity detectable through its own data directory,
// never the ~/.gemini directory shared with the Gemini CLI.
func detectTestAgy(t *testing.T, home string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".gemini", "antigravity-cli"), 0700); err != nil {
		t.Fatal(err)
	}
}

func agyHooksPath(home string) string { return filepath.Join(home, ".gemini", "config", "hooks.json") }

// runTestService starts the daemon on a fresh private state directory and
// returns a stop function plus a client for its local socket.
func runTestService(t *testing.T, creds string) (func(), *http.Client) {
	t.Helper()
	dir := privateTemp(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, dir, func(context.Context, Event) result { return result{Code: "accepted"} }, creds)
	}()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dialLocal(ctx, dir) }}
	client := &http.Client{Transport: tr, Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("http://local/v1/status")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop := func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		tr.CloseIdleConnections()
	}
	return stop, client
}

// waitForJoin waits for the start-up join: it writes the config first and the
// hourly stamp last.
func waitForJoin(t *testing.T, stop func(), creds, hooks string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(hooks); err == nil {
			if raw, err := os.ReadFile(agentStatePath(creds)); err == nil {
				var st agentState
				if json.Unmarshal(raw, &st) == nil && st.Refreshed > 0 {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatal("service did not join the detected agent")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func agyTestCommands(t *testing.T, raw []byte) []string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 1 {
		t.Fatalf("hooks.json holds more than our group: %v", doc)
	}
	group, ok := doc["shinphony"].(map[string]any)
	if !ok {
		t.Fatalf("hooks.json has no shinphony group: %s", raw)
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, v := range x {
				if k == "command" {
					if s, ok := v.(string); ok {
						out = append(out, s)
					}
					continue
				}
				walk(v)
			}
		case []any:
			for _, v := range x {
				walk(v)
			}
		}
	}
	walk(group)
	sort.Strings(out)
	return out
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func findAgentRecord(records []agentRecord, agent string) agentRecord {
	for _, r := range records {
		if r.ID == agent {
			return r
		}
	}
	return agentRecord{}
}

func readAgentScope(t *testing.T, creds string) agentState {
	t.Helper()
	raw, err := os.ReadFile(agentStatePath(creds))
	if err != nil {
		t.Fatal(err)
	}
	var st agentState
	if err = json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// The pre-agy state: records for codex and claude, no scope record. The first
// refresh after the update must join agy, write the scope once, and leave the
// config exactly as setup would have written it.
func TestAutoScopeRefreshJoinsDetectedAgentAfterMigration(t *testing.T) {
	home, creds, exe, m := agentTestHome(t)
	installTestAgent(t, m, exe, "codex")
	installTestAgent(t, m, exe, "claude")
	if _, err := os.Stat(agentStatePath(creds)); !os.IsNotExist(err) {
		t.Fatal("pre-agy state must have no scope record", err)
	}
	detectTestAgy(t, home)

	records, err := refreshIntegrationsAt(m, exe, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := readAgentScope(t, creds)
	if !st.Auto || len(st.Agents) != 0 {
		t.Fatalf("migration did not record the auto scope: %+v", st)
	}
	if info, err := os.Stat(agentStatePath(creds)); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("scope record is not private", err)
	}
	raw := mustReadFile(t, agyHooksPath(home))
	want := []string{}
	for _, event := range []string{"SessionStart", "PreInvocation", "PreToolUse", "PostToolUse", "Stop"} {
		want = append(want, "'"+exe+"' agy-hook "+event)
	}
	sort.Strings(want)
	if got := agyTestCommands(t, raw); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("installed commands differ:\n got %v\nwant %v", got, want)
	}
	if got := findAgentRecord(records, "agy"); got.State != "installed" {
		t.Fatalf("agy not reported installed: %+v", got)
	}
	if !bytes.Contains(mustReadFile(t, filepath.Join(home, "codex", "config.toml")), []byte(managedPrefix)) {
		t.Fatal("installed codex agent was not refreshed")
	}
}

// A single-agent scope never grows on its own: only "Supported agents" joins
// agents detected later.
func TestExplicitScopeDoesNotJoinNewAgents(t *testing.T) {
	home, creds, exe, m := agentTestHome(t)
	installTestAgent(t, m, exe, "codex")
	detectTestAgy(t, home)
	if err := recordSetupScope(m, "codex"); err != nil {
		t.Fatal(err)
	}
	records, err := refreshIntegrationsAt(m, exe, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(agyHooksPath(home)); !os.IsNotExist(err) {
		t.Fatal("explicit scope installed a new agent", err)
	}
	st := readAgentScope(t, creds)
	if st.Auto || len(st.Agents) != 1 || st.Agents[0] != "codex" {
		t.Fatalf("scope changed: %+v", st)
	}
	if got := findAgentRecord(records, "agy"); got.State != "" {
		t.Fatalf("agy reported for an explicit scope: %+v", got)
	}
}

// A group the user disabled is a refusal, not an error: our agents keep being
// refreshed, agy is skipped with a code the App can show, and the file stays
// byte-identical.
func TestAutoRefreshSkipsDisabledGroupAndKeepsOthers(t *testing.T) {
	home, _, exe, m := agentTestHome(t)
	installTestAgent(t, m, exe, "codex")
	installTestAgent(t, m, exe, "claude")
	detectTestAgy(t, home)
	dir := filepath.Join(home, ".gemini", "config")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	disabled := `{"shinphony":{"enabled":false}}`
	if err := os.WriteFile(agyHooksPath(home), []byte(disabled), 0600); err != nil {
		t.Fatal(err)
	}

	records, err := refreshIntegrationsAt(m, exe, time.Now())
	if err != nil {
		t.Fatalf("a refusal on a newly detected agent is not an error: %v", err)
	}
	if got := string(mustReadFile(t, agyHooksPath(home))); got != disabled {
		t.Fatalf("refused config was changed: %s", got)
	}
	if got := findAgentRecord(records, "agy"); got.State != "skipped" || got.Reason != "hooks_disabled" {
		t.Fatalf("agy not reported skipped: %+v", got)
	}
	status, err := agentRecords(m)
	if err != nil {
		t.Fatal(err)
	}
	if got := findAgentRecord(status, "agy"); got.State != "skipped" || got.Reason != "hooks_disabled" {
		t.Fatalf("status lost the refusal: %+v", got)
	}
	for _, agent := range []string{"codex", "claude"} {
		if got := findAgentRecord(status, agent); got.State != "installed" {
			t.Fatalf("%s lost its installed state: %+v", agent, got)
		}
	}
}

// An unreadable config is refused once and then left alone until the file
// changes, so a broken file is not rewritten or retried every hour.
func TestRefusedAgentRetriesOnlyAfterConfigChange(t *testing.T) {
	home, _, exe, m := agentTestHome(t)
	installTestAgent(t, m, exe, "codex")
	detectTestAgy(t, home)
	dir := filepath.Join(home, ".gemini", "config")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	broken := `{"shinphony":`
	if err := os.WriteFile(agyHooksPath(home), []byte(broken), 0600); err != nil {
		t.Fatal(err)
	}
	calls, applies := 0, 0
	previous := configureAgent
	configureAgent = func(m notifier.Manager, agent, name string, apply bool) error {
		if agent == "agy" {
			calls++
			if apply {
				applies++
			}
		}
		return previous(m, agent, name, apply)
	}
	defer func() { configureAgent = previous }()

	now := time.Now()
	records, err := refreshIntegrationsAt(m, exe, now)
	if err != nil {
		t.Fatal(err)
	}
	if calls == 0 {
		t.Fatal("refused agent was never attempted")
	}
	if got := findAgentRecord(records, "agy"); got.State != "skipped" || got.Reason != "invalid_agy_config" {
		t.Fatalf("agy not reported skipped: %+v", got)
	}
	if got := string(mustReadFile(t, agyHooksPath(home))); got != broken {
		t.Fatalf("refused config was changed: %s", got)
	}
	attempted := calls
	// The hourly limit has expired, but the unchanged file must not be retried.
	records, err = refreshIntegrationsAt(m, exe, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if calls != attempted {
		t.Fatalf("unchanged refused config retried: %d -> %d", attempted, calls)
	}
	if got := findAgentRecord(records, "agy"); got.State != "skipped" || got.Reason != "invalid_agy_config" {
		t.Fatalf("stored refusal lost: %+v", got)
	}
	// A changed file is an explicit reason to try again, and now it installs.
	if err := os.WriteFile(agyHooksPath(home), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	records, err = refreshIntegrationsAt(m, exe, now.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// One preflight plus one apply writes the agent.
	if calls != attempted+2 {
		t.Fatalf("changed config not retried: %d -> %d", attempted, calls)
	}
	if applies != 1 {
		t.Fatalf("retry did not apply the config: %d", applies)
	}
	if got := findAgentRecord(records, "agy"); got.State != "installed" {
		t.Fatalf("agy not installed after the change: %+v", got)
	}
	if len(agyTestCommands(t, mustReadFile(t, agyHooksPath(home)))) != 5 {
		t.Fatal("installed group is incomplete")
	}
}

// Two refreshes of the same state must not rewrite anything.
func TestRefreshIsIdempotent(t *testing.T) {
	home, creds, exe, m := agentTestHome(t)
	installTestAgent(t, m, exe, "codex")
	installTestAgent(t, m, exe, "claude")
	detectTestAgy(t, home)
	now := time.Now()
	if _, err := refreshIntegrationsAt(m, exe, now); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		filepath.Join(home, "codex", "config.toml"),
		filepath.Join(home, "codex", "hooks.json"),
		filepath.Join(home, "claude", "settings.json"),
		agyHooksPath(home),
		filepath.Join(creds, "codex-install.json"),
		filepath.Join(creds, "claude-install.json"),
		filepath.Join(creds, "agy-install.json"),
	}
	first := map[string][]byte{}
	for _, path := range paths {
		first[path] = mustReadFile(t, path)
	}
	if _, err := refreshIntegrationsAt(m, exe, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if got := mustReadFile(t, path); !bytes.Equal(got, first[path]) {
			t.Fatalf("second refresh rewrote %s", path)
		}
	}
}

// A user who never set up an agent gets no scope and no hook config.
func TestRefreshWithoutInstallRecordsDoesNothing(t *testing.T) {
	home, creds, exe, m := agentTestHome(t)
	detectTestAgy(t, home)
	records, err := refreshIntegrationsAt(m, exe, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("refresh reported work without a scope: %+v", records)
	}
	if _, err = os.Stat(agentStatePath(creds)); !os.IsNotExist(err) {
		t.Fatal("a scope was written without any install record", err)
	}
	if _, err = os.Stat(agyHooksPath(home)); !os.IsNotExist(err) {
		t.Fatal("an agent was installed without a scope", err)
	}
}

// Setting up one agent does not shrink an existing auto scope, so agents
// detected later keep joining.
func TestSetupKeepsAutoScope(t *testing.T) {
	defer func(old func() (int, int, error)) { checkCodexHooks = old }(checkCodexHooks)
	checkCodexHooks = func() (int, int, error) { return 0, 0, errors.New("codex_not_found") }
	home, creds, exe, m := agentTestHome(t)
	installTestAgent(t, m, exe, "codex")
	if _, err := refreshIntegrationsAt(m, exe, time.Now()); err != nil {
		t.Fatal(err)
	}
	detectTestAgy(t, home)
	if err := configureSetupAgents(m, "agy", exe); err != nil {
		t.Fatal(err)
	}
	st := readAgentScope(t, creds)
	if !st.Auto {
		t.Fatalf("single-agent setup shrank the auto scope: %+v", st)
	}
	if len(agyTestCommands(t, mustReadFile(t, agyHooksPath(home)))) != 5 {
		t.Fatal("explicit agy setup did not install the group")
	}
}

// The service joins detected agents off the hot path at start, at most once an
// hour, and reports the result through status.
func TestServiceStartJoinsDetectedAgentOnceAnHour(t *testing.T) {
	defer func(old func() (int, int, error)) { checkCodexHooks = old }(checkCodexHooks)
	checkCodexHooks = func() (int, int, error) { return 0, 0, errors.New("codex_not_found") }
	home, creds, exe, m := agentTestHome(t)
	// The user chose "Supported agents" when codex was the only agent around.
	if err := os.MkdirAll(filepath.Join(home, "codex"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := configureSetupAgents(m, "auto", exe); err != nil {
		t.Fatal(err)
	}
	detectTestAgy(t, home)

	stop, client := runTestService(t, creds)
	waitForJoin(t, stop, creds, agyHooksPath(home))
	resp, err := client.Get("http://local/v1/status")
	if err != nil {
		stop()
		t.Fatal(err)
	}
	var status struct {
		Agents []agentRecord `json:"agents"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&status)
	resp.Body.Close()
	if err != nil {
		stop()
		t.Fatal(err)
	}
	if got := findAgentRecord(status.Agents, "agy"); got.State != "installed" {
		stop()
		t.Fatalf("status does not show the joined agent: %+v", status.Agents)
	}
	before := mustReadFile(t, agyHooksPath(home))
	info, err := os.Stat(agyHooksPath(home))
	if err != nil {
		stop()
		t.Fatal(err)
	}
	refreshed := readAgentScope(t, creds).Refreshed
	stop()

	// A second start inside the hour must not do any work.
	stop, _ = runTestService(t, creds)
	time.Sleep(300 * time.Millisecond)
	if got := mustReadFile(t, agyHooksPath(home)); !bytes.Equal(got, before) {
		stop()
		t.Fatal("second start within the hour rewrote the config")
	}
	after, err := os.Stat(agyHooksPath(home))
	if err != nil {
		stop()
		t.Fatal(err)
	}
	if !after.ModTime().Equal(info.ModTime()) {
		stop()
		t.Fatal("second start within the hour touched the config")
	}
	if got := readAgentScope(t, creds).Refreshed; got != refreshed {
		stop()
		t.Fatalf("second start refreshed again: %d -> %d", refreshed, got)
	}
	stop()
}

// A removal the user asked for must stick: the automatic join never adds the
// agent back, and only a later setup does.
func TestUninstalledAgentStaysRemoved(t *testing.T) {
	defer func(old func() (int, int, error)) { checkCodexHooks = old }(checkCodexHooks)
	checkCodexHooks = func() (int, int, error) { return 0, 0, errors.New("codex_not_found") }
	home, creds, exe, m := agentTestHome(t)
	installTestAgent(t, m, exe, "codex")
	if _, err := refreshIntegrationsAt(m, exe, time.Now()); err != nil {
		t.Fatal(err)
	}
	if st := readAgentScope(t, creds); !st.Auto {
		t.Fatalf("migration did not record the auto scope: %+v", st)
	}
	if err := m.Uninstall("codex"); err != nil {
		t.Fatal(err)
	}
	if err := recordAgentUninstall(m, "codex"); err != nil {
		t.Fatal(err)
	}
	records, err := refreshIntegrationsAt(m, exe, time.Now().Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if installed, err := m.InstalledAgents(); err != nil || len(installed) != 0 {
		t.Fatalf("uninstalled agent came back: %v %v", installed, err)
	}
	if got := findAgentRecord(records, "codex"); got.State != "" {
		t.Fatalf("refresh reported the uninstalled agent: %+v", got)
	}
	// The uninstall removed the config it had created; a reinstall would put it
	// back with our hook.
	if raw, err := os.ReadFile(filepath.Join(home, "codex", "config.toml")); err == nil && bytes.Contains(raw, []byte(managedPrefix)) {
		t.Fatal("uninstalled agent config was rewritten")
	}
	status, err := agentRecords(m)
	if err != nil {
		t.Fatal(err)
	}
	if got := findAgentRecord(status, "codex"); got.State != "not_detected" {
		t.Fatalf("uninstalled agent is not quiet in status: %+v", got)
	}
	// An explicit setup of that agent is the user asking for it again.
	if err := configureSetupAgents(m, "codex", exe); err != nil {
		t.Fatal(err)
	}
	if st := readAgentScope(t, creds); slices.Contains(st.Excluded, "codex") {
		t.Fatalf("explicit setup did not clear the exclusion: %+v", st)
	}
	if installed, err := m.InstalledAgents(); err != nil || len(installed) != 1 || installed[0] != "codex" {
		t.Fatalf("explicit setup did not reinstall: %v %v", installed, err)
	}
}

// Choosing "Supported agents" again from the App is also an explicit request:
// it clears every recorded removal.
func TestAutoSetupClearsUninstallExclusion(t *testing.T) {
	defer func(old func() (int, int, error)) { checkCodexHooks = old }(checkCodexHooks)
	checkCodexHooks = func() (int, int, error) { return 0, 0, errors.New("codex_not_found") }
	_, creds, exe, m := agentTestHome(t)
	installTestAgent(t, m, exe, "codex")
	if _, err := refreshIntegrationsAt(m, exe, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := m.Uninstall("codex"); err != nil {
		t.Fatal(err)
	}
	if err := recordAgentUninstall(m, "codex"); err != nil {
		t.Fatal(err)
	}
	if err := configureSetupAgents(m, "auto", exe); err != nil {
		t.Fatal(err)
	}
	st := readAgentScope(t, creds)
	if len(st.Excluded) != 0 {
		t.Fatalf("auto setup kept the exclusion: %+v", st)
	}
	if !st.Auto {
		t.Fatalf("auto setup shrank the scope: %+v", st)
	}
	if installed, err := m.InstalledAgents(); err != nil || len(installed) != 1 || installed[0] != "codex" {
		t.Fatalf("auto setup did not reinstall: %v %v", installed, err)
	}
}

// Two refreshes at once must not both install, and must not fail each other:
// the second waits for the lock, reloads the state and only refreshes.
func TestConcurrentRefreshesInstallOnce(t *testing.T) {
	home, _, exe, m := agentTestHome(t)
	installTestAgent(t, m, exe, "codex")
	detectTestAgy(t, home)
	var mu sync.Mutex
	preflights := 0
	previous := configureAgent
	configureAgent = func(m notifier.Manager, agent, name string, apply bool) error {
		if agent == "agy" && !apply {
			mu.Lock()
			preflights++
			mu.Unlock()
		}
		return previous(m, agent, name, apply)
	}
	defer func() { configureAgent = previous }()

	now := time.Now()
	start := make(chan struct{})
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			_, err := refreshIntegrationsAt(m, exe, now)
			errs <- err
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if preflights != 1 {
		t.Fatalf("agent installed %d times", preflights)
	}
	if installed, err := m.InstalledAgents(); err != nil || len(installed) != 2 {
		t.Fatalf("wrong install state: %v %v", installed, err)
	}
	first := mustReadFile(t, agyHooksPath(home))
	if _, err := refreshIntegrationsAt(m, exe, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustReadFile(t, agyHooksPath(home)), first) {
		t.Fatal("a later refresh changed the config")
	}
}

// A refresh that finds the lock held does not work in parallel: it waits
// briefly and leaves the work to the holder.
func TestRefreshSkipsWhileAnotherRefreshHoldsTheLock(t *testing.T) {
	home, creds, exe, m := agentTestHome(t)
	installTestAgent(t, m, exe, "codex")
	detectTestAgy(t, home)
	previous := refreshLockWait
	refreshLockWait = 40 * time.Millisecond
	defer func() { refreshLockWait = previous }()

	unlock, err := refreshLock(creds)
	if err != nil {
		t.Fatal(err)
	}
	records, err := refreshIntegrationsAt(m, exe, time.Now())
	if err != nil {
		t.Fatalf("a busy refresh is not an error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("refresh worked while locked: %+v", records)
	}
	if _, err = os.Stat(agyHooksPath(home)); !os.IsNotExist(err) {
		t.Fatal("locked refresh installed an agent", err)
	}
	unlock()
	records, err = refreshIntegrationsAt(m, exe, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := findAgentRecord(records, "agy"); got.State != "installed" {
		t.Fatalf("refresh did not run after the lock was released: %+v", records)
	}
}

// The service start only joins agents detected since setup; it never rewrites
// the config of an installed one, not even for a different executable path.
func TestServiceStartJoinsOnlyNewAgents(t *testing.T) {
	defer func(old func() (int, int, error)) { checkCodexHooks = old }(checkCodexHooks)
	checkCodexHooks = func() (int, int, error) { return 0, 0, errors.New("codex_not_found") }
	home, creds, exe, m := agentTestHome(t)
	if err := os.MkdirAll(filepath.Join(home, "codex"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := configureSetupAgents(m, "auto", exe); err != nil {
		t.Fatal(err)
	}
	codexConfig := filepath.Join(home, "codex", "config.toml")
	before := mustReadFile(t, codexConfig)
	info, err := os.Stat(codexConfig)
	if err != nil {
		t.Fatal(err)
	}
	detectTestAgy(t, home)

	refreshedInstalled := 0
	previous := configureAgent
	configureAgent = func(m notifier.Manager, agent, name string, apply bool) error {
		if agent == "codex" {
			refreshedInstalled++
		}
		return previous(m, agent, name, apply)
	}
	defer func() { configureAgent = previous }()

	stop, _ := runTestService(t, creds)
	waitForJoin(t, stop, creds, agyHooksPath(home))
	stop()
	if refreshedInstalled != 0 {
		t.Fatalf("service start reconfigured an installed agent %d times", refreshedInstalled)
	}
	if got := mustReadFile(t, codexConfig); !bytes.Equal(got, before) {
		t.Fatal("service start rewrote an installed config")
	}
	after, err := os.Stat(codexConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(info.ModTime()) {
		t.Fatal("service start touched an installed config")
	}
}
