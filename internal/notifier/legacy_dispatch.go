package notifier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

func networkContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), networkDeadline)
}
func readBounded(in io.Reader, n int) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(in, int64(n+1)))
	if e != nil || len(b) > n {
		return nil, errConfig
	}
	return b, nil
}
func run(args []string, in io.Reader, out, errOut io.Writer, r relay) int {
	if len(args) == 0 || args[0] == "help" {
		fmt.Fprintln(out, "shinphony-notify: inspect | pair PROFILE LANE HOST (code on stdin) | send PROFILE STATUS | codex-hook PROFILE (JSON on stdin) | codex-notify PROFILE JSON")
		return 0
	}
	if args[0] == "inspect" {
		json.NewEncoder(out).Encode(map[string]any{"schema": 1, "version": "0.1.0-dev", "os": runtime.GOOS, "arch": runtime.GOARCH, "daemon": false})
		return 0
	}
	s, e := defaultStore()
	if e != nil {
		if args[0] == "codex-hook" || args[0] == "claude-hook-all" {
			fmt.Fprintln(out, `{}`)
			return 0
		}
		if args[0] == "codex-notify" || args[0] == "codex-notify-all" {
			return 0
		}
		return 1
	}
	fail := func(e error) int { fmt.Fprintln(errOut, e.Error()); return 1 }
	switch args[0] {
	case "doctor":
		if len(args) != 4 {
			return fail(errConfig)
		}
		result, e := s.doctor(args[1], args[2], args[3])
		if e != nil {
			return fail(e)
		}
		json.NewEncoder(out).Encode(result)
		return 0
	case "reset-profile":
		// Caller first revokes this device/host at the relay, then clears only
		// the named destination. Other phones and agent hooks are untouched.
		if len(args) != 2 {
			return fail(errConfig)
		}
		if e = s.initialize(); e != nil {
			return fail(e)
		}
		p, e := s.path(args[1])
		if e != nil {
			return fail(e)
		}
		lock := filepath.Join(s.dir, args[1]+".lock")
		if info, e := os.Lstat(lock); e == nil {
			if e = checkPrivate(lock, false); e != nil {
				return fail(e)
			}
			if time.Since(info.ModTime()) < 30*time.Second {
				return fail(errors.New("busy_or_interrupted_install"))
			}
			if e = os.Remove(lock); e != nil {
				return fail(errConfig)
			}
		} else if !os.IsNotExist(e) {
			return fail(errConfig)
		}
		unlock, e := s.lock(args[1])
		if e != nil {
			return fail(e)
		}
		defer unlock()
		for _, path := range []string{p, filepath.Join(s.dir, args[1]+".pending")} {
			if _, e := os.Lstat(path); os.IsNotExist(e) {
				continue
			}
			if e := checkPrivate(path, false); e != nil {
				return fail(e)
			}
			if e := os.Remove(path); e != nil {
				return fail(errConfig)
			}
		}
		fmt.Fprintln(out, `{"reset":true}`)
		return 0
	case "preflight-codex", "install-codex", "preflight-claude", "install-claude":
		home, e := os.UserHomeDir()
		if e != nil {
			return fail(errConfig)
		}
		exe, e := os.Executable()
		if e != nil {
			return fail(errConfig)
		}
		if strings.HasSuffix(args[0], "claude") {
			e = s.configureAgentWith("claude", claudeConfigPath(home), exe, args[0] == "install-claude", proposedClaude, stripClaude)
		} else {
			e = s.configureCodex(codexConfigPath(home), exe, args[0] == "install-codex")
		}
		if e != nil {
			return fail(e)
		}
		fmt.Fprintln(out, `{"ready":true,"restartAgent":true}`)
		return 0
	case "uninstall-codex", "uninstall-claude":
		strip := stripFunc(nil)
		if args[0] == "uninstall-claude" {
			strip = stripClaude
		}
		if e = s.uninstallAgentWith(strings.TrimPrefix(args[0], "uninstall-"), strip); e != nil {
			return fail(e)
		}
		fmt.Fprintln(out, `{"removed":true}`)
		return 0
	case "profile-status":
		if len(args) != 4 {
			return fail(errConfig)
		}
		c, e := s.load(args[1])
		if e == nil {
			if c.Lane != args[2] || c.Host != args[3] {
				return fail(errConfig)
			}
			fmt.Fprintln(out, `{"paired":true}`)
			return 0
		}
		if e = s.initialize(); e != nil {
			return fail(e)
		}
		p, e := s.path(args[1])
		if e != nil {
			return fail(e)
		}
		if _, e = os.Lstat(p); !os.IsNotExist(e) {
			return fail(errConfig)
		}
		if _, e = os.Lstat(filepath.Join(s.dir, args[1]+".pending")); !os.IsNotExist(e) {
			return fail(errors.New("pairing_needs_reconciliation"))
		}
		fmt.Fprintln(out, `{"paired":false}`)
		return 0
	case "codex-notify-all", "claude-hook-all":
		var ev event
		var ok bool
		if args[0] == "claude-hook-all" {
			defer fmt.Fprintln(out, `{}`)
			raw, e := readBounded(in, 262144)
			if e != nil {
				return 0
			}
			ev, ok = claudeEvent(raw)
		} else {
			if len(args) != 2 {
				return 0
			}
			ev, ok = codexEvent([]byte(args[1]), true)
		}
		if !ok {
			return 0
		}
		files, _ := filepath.Glob(filepath.Join(s.dir, "*.json"))
		ctx, cancel := networkContext()
		defer cancel()
		var wg sync.WaitGroup
		count := 0
		for _, p := range files {
			c, e := s.load(strings.TrimSuffix(filepath.Base(p), ".json"))
			if e != nil {
				continue
			}
			if count >= 10 {
				break
			}
			count++
			wg.Add(1)
			go func(c credential) { defer wg.Done(); _ = r.send(ctx, c, ev) }(c)
		}
		wg.Wait()
		return 0
	case "pair":
		if len(args) != 4 {
			return fail(errConfig)
		}
		raw, e := readBounded(in, 128)
		if e != nil {
			return fail(errConfig)
		}
		if e = s.pair(args[1], args[2], args[3], strings.TrimSpace(string(raw)), r); e != nil {
			return fail(e)
		}
		fmt.Fprintln(out, `{"paired":true,"deliveryVerified":false}`)
		return 0
	case "send":
		if len(args) != 3 {
			return fail(errConfig)
		}
		c, e := s.load(args[1])
		if e != nil {
			return fail(errConfig)
		}
		ctx, cancel := networkContext()
		defer cancel()
		if e = r.send(ctx, c, event{randomID(), args[2]}); e != nil {
			return fail(e)
		}
		fmt.Fprintln(out, `{"accepted":true,"deliveryVerified":false}`)
		return 0
	case "codex-hook", "codex-notify":
		// Always succeed, and never emit instructions which influence the agent loop.
		if args[0] == "codex-hook" {
			defer fmt.Fprintln(out, `{}`)
		}
		var raw []byte
		if args[0] == "codex-hook" && len(args) == 2 {
			raw, e = readBounded(in, 262144)
		} else if args[0] == "codex-notify" && len(args) == 3 {
			raw = []byte(args[2])
		} else {
			return 0
		}
		if e != nil {
			return 0
		}
		ev, ok := codexEvent(raw, args[0] == "codex-notify")
		if !ok {
			return 0
		}
		c, e := s.load(args[1])
		if e != nil {
			return 0
		}
		ctx, cancel := networkContext()
		defer cancel()
		_ = r.send(ctx, c, ev)
		return 0
	default:
		return fail(errConfig)
	}
}
