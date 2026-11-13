package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Codex runs a hook only after it is reviewed (/hooks in the TUI), which
// records the hook's hash under hooks.state in config.toml. We never record
// that on our own: `trust-codex-hooks` does it for our hooks only, when the
// user asks, through Codex's app-server exactly as approving in /hooks would.

type codexHook struct {
	Key         string `json:"key"`
	Command     string `json:"command"`
	CurrentHash string `json:"currentHash"`
	TrustStatus string `json:"trustStatus"`
}

// codexBinary finds codex for a daemon whose PATH lacks the user's shell
// setup (npm/nvm, Homebrew, ~/.local/bin).
func codexBinary() (string, error) {
	if p, err := exec.LookPath("codex"); err == nil {
		return p, nil
	}
	home, _ := os.UserHomeDir()
	candidates := []string{filepath.Join(home, ".local", "bin", "codex"), "/opt/homebrew/bin/codex", "/usr/local/bin/codex", filepath.Join(home, ".npm-global", "bin", "codex")}
	nvm, _ := filepath.Glob(filepath.Join(home, ".nvm", "versions", "node", "*", "bin", "codex"))
	sort.Sort(sort.Reverse(sort.StringSlice(nvm)))
	for _, p := range append(nvm, candidates...) {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("codex_not_found")
}

type codexAppServer struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan []byte
	next  int
}

func startCodexAppServer(ctx context.Context) (*codexAppServer, error) {
	bin, err := codexBinary()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, bin, "app-server")
	// An npm-installed codex is a node script; node sits next to it.
	cmd.Env = append(os.Environ(), "PATH="+filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Dir = os.TempDir()
	cmd.WaitDelay = time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	s := &codexAppServer{cmd: cmd, stdin: stdin, lines: make(chan []byte, 64), next: 1}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			s.lines <- append([]byte(nil), sc.Bytes()...)
		}
		close(s.lines)
	}()
	if _, err = s.call(ctx, "initialize", map[string]any{"clientInfo": map[string]any{"name": "shinphony-hook", "version": version}}); err != nil {
		s.close()
		return nil, err
	}
	if err = s.send(map[string]any{"jsonrpc": "2.0", "method": "initialized"}); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *codexAppServer) send(msg any) error {
	b, _ := json.Marshal(msg)
	_, err := s.stdin.Write(append(b, '\n'))
	return err
}

func (s *codexAppServer) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := s.next
	s.next++
	if err := s.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("codex_app_server_timeout")
		case line, ok := <-s.lines:
			if !ok {
				return nil, errors.New("codex_app_server_exited")
			}
			var resp struct {
				ID     *int            `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  *struct{}       `json:"error"`
			}
			if json.Unmarshal(line, &resp) != nil || resp.ID == nil || *resp.ID != id {
				continue
			}
			if resp.Error != nil {
				return nil, errors.New("codex_app_server_error")
			}
			return resp.Result, nil
		}
	}
}

func (s *codexAppServer) close() {
	s.stdin.Close()
	done := make(chan struct{})
	go func() { s.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		s.cmd.Process.Kill()
		<-done
	}
}

// ourCodexHooks lists our hooks (codex-hook-all) as Codex sees them.
func ourCodexHooks(ctx context.Context, s *codexAppServer) ([]codexHook, error) {
	raw, err := s.call(ctx, "hooks/list", map[string]any{"cwds": []string{os.TempDir()}})
	if err != nil {
		return nil, err
	}
	var res struct {
		Data []struct {
			Hooks []codexHook `json:"hooks"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &res) != nil {
		return nil, errors.New("codex_app_server_error")
	}
	var ours []codexHook
	for _, d := range res.Data {
		for _, h := range d.Hooks {
			if strings.HasSuffix(strings.TrimSpace(h.Command), " codex-hook-all") {
				ours = append(ours, h)
			}
		}
	}
	return ours, nil
}

// codexHookTrust reports how many of our hooks Codex will run; with trust it
// first records the untrusted ones as reviewed.
func codexHookTrust(trust bool) (trusted, untrusted int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := startCodexAppServer(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer s.close()
	hooks, err := ourCodexHooks(ctx, s)
	if err != nil {
		return 0, 0, err
	}
	state := map[string]any{}
	for _, h := range hooks {
		if h.TrustStatus == "trusted" {
			trusted++
		} else {
			untrusted++
			state[h.Key] = map[string]any{"trusted_hash": h.CurrentHash}
		}
	}
	if trust && len(state) > 0 {
		if _, err = s.call(ctx, "config/value/write", map[string]any{"keyPath": "hooks.state", "value": state, "mergeStrategy": "upsert"}); err != nil {
			return trusted, untrusted, err
		}
		trusted, untrusted = trusted+untrusted, 0
	}
	return trusted, untrusted, nil
}
