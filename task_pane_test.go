package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTaskPaneRealAncestry(t *testing.T) {
	if os.Getenv("SHINPHONY_TEST_TASK_PANE") != "1" {
		t.Skip("opt-in live read-only tmux check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	socket, pane := discoverTaskPane(ctx, os.Getpid())
	if socket == "" || pane == "" {
		t.Fatal("current process cannot be matched to a tmux pane")
	}
	t.Logf("verified pane %s", pane)
}

func TestTmuxUTF8WithoutLocale(t *testing.T) {
	if os.Getenv("SHINPHONY_TEST_TASK_PANE") != "1" {
		t.Skip("opt-in live read-only tmux check")
	}
	t.Setenv("LANG", "")
	t.Setenv("LC_ALL", "C")
	t.Setenv("LC_CTYPE", "C")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	socket, pane := discoverTaskPane(ctx, os.Getpid())
	if socket == "" || pane == "" {
		t.Fatal("pane discovery failed with C locale")
	}
	parts := strings.Split(socket, ",")
	path := strings.Join(parts[:len(parts)-2], ",")
	want := "field\t中文"
	got, err := tmuxOutput(ctx, "-S", path, "display-message", "-p", "-t", pane, want)
	if err != nil || strings.TrimSuffix(got, "\n") != want {
		t.Fatalf("UTF-8/tab roundtrip: %q, %v", got, err)
	}
}

func TestMatchTaskPane(t *testing.T) {
	for _, tc := range []struct{ name, raw, tmux, pane string }{
		{"unique", "/tmp/tmux/default\t10\t%0\t30\n/tmp/tmux/default\t10\t%1\t99\n", "/tmp/tmux/default,10,0", "%0"},
		{"linked", "/tmp/tmux/default\t10\t%0\t30\n/tmp/tmux/default\t10\t%0\t30\n", "/tmp/tmux/default,10,0", "%0"},
		{"unrelated_shared_daemon", "/tmp/tmux/default\t10\t%0\t99", "", ""},
		{"ambiguous", "/tmp/tmux/default\t10\t%0\t30\n/tmp/tmux/default\t10\t%1\t40", "", ""},
		{"malformed", "relative\t10\t%0\t30", "", ""},
		{"empty", "", "", ""},
		{"comma_socket", "/tmp/with,comma\t10\t%0\t30", "/tmp/with,comma,10,0", "%0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := matchTaskPane(tc.raw, map[int]bool{30: true, 40: true})
			if a != tc.tmux || b != tc.pane {
				t.Fatalf("%q %q", a, b)
			}
		})
	}
}
