package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTaskIntentRestoresUniqueAncestorPane(t *testing.T) {
	exe := "/private/bin/shinphony-hook-" + strings.Repeat("a", 64)
	output, _ := taskIntentOutput([]string{"task", "completed"})
	raw := intentHook(taskIntentCommand(exe, "task", "completed", false), output)
	socket := filepath.Join(t.TempDir(), "default")
	calls := 0
	discover := func(ctx context.Context, pid int) (string, string) {
		calls++
		if pid != 42 {
			t.Fatal("wrong owner", pid)
		}
		return matchTaskPane(socket+"\t10\t%3\t41\n", map[int]bool{42: true, 41: true})
	}
	forwardTaskIntent(context.Background(), raw, exe, 42, func(string) string { return "" }, discover, func(e hookEvent) (hookAcceptance, error) {
		if e.Source == nil || e.Source.Tmux != socket+",10,0" || e.Source.Pane != "%3" || e.Source.ParentPID != 42 || e.Source.Thread != "runtime-thread" {
			t.Fatalf("missing recovered source: %+v", e.Source)
		}
		return hookAcceptance{}, nil
	})
	if calls != 1 {
		t.Fatal("discovery calls", calls)
	}
}

func TestTaskSourcePrecedenceAndBoundedFallback(t *testing.T) {
	for _, tc := range []struct {
		name            string
		env             map[string]string
		raw, tmux, pane string
		calls           int
	}{
		{"hc", map[string]string{"HC_TERMINAL_ID": "t1", "HC_TERMINAL_SOCKET": "/private/hc", "TMUX": "outer", "TMUX_PANE": "%9"}, "", "outer", "%9", 0},
		{"partial_hc_id", map[string]string{"HC_TERMINAL_ID": "bad"}, "", "", "", 0},
		{"partial_hc_socket", map[string]string{"HC_TERMINAL_SOCKET": "invalid"}, "", "", "", 0},
		{"complete_tmux", map[string]string{"TMUX": "given", "TMUX_PANE": "%2"}, "", "given", "%2", 0},
		{"partial_tmux", map[string]string{"TMUX": "given"}, "/private/test/default\t10\t%3\t41\n", "/private/test/default,10,0", "%3", 1},
		{"ambiguous", nil, "/private/test/default\t10\t%3\t41\n/private/test/default\t10\t%4\t42\n", "", "", 1},
		{"no_match", nil, "/private/test/default\t10\t%3\t99\n", "", "", 1},
		{"query_failed", nil, "", "", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "default")
			tc.raw = strings.ReplaceAll(tc.raw, "/private/test/default", socket)
			tc.tmux = strings.ReplaceAll(tc.tmux, "/private/test/default", socket)
			calls := 0
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			source := resolveTaskSource(ctx, 42, "thread", func(k string) string { return tc.env[k] }, func(got context.Context, pid int) (string, string) {
				calls++
				if got != ctx || pid != 42 {
					t.Fatal("changed caller context/owner")
				}
				return matchTaskPane(tc.raw, map[int]bool{41: true, 42: true})
			})
			if calls != tc.calls || source.Tmux != tc.tmux || source.Pane != tc.pane {
				t.Fatalf("calls=%d source=%+v", calls, source)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolveTaskSource(ctx, 42, "thread", func(string) string { return "" }, func(context.Context, int) (string, string) { t.Fatal("discovery after deadline"); return "", "" })
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	start := time.Now()
	source := resolveTaskSource(ctx, 42, "thread", func(string) string { return "" }, func(got context.Context, _ int) (string, string) { <-got.Done(); return "", "" })
	if source.Pane != "" || time.Since(start) > time.Second {
		t.Fatal("timeout fallback was not bounded")
	}
}
