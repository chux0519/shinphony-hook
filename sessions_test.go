package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionsOutputMatchesAppDiscoveryFormat(t *testing.T) {
	var out bytes.Buffer
	find := func(name string) string {
		if name == "tmux" || name == "screen" {
			return "/fake/" + name
		}
		return ""
	}
	run := func(_ context.Context, path string, args []string) []byte {
		if path == "/fake/tmux" {
			if args[0] != "-u" || args[1] != "list-sessions" || args[3] != tmuxSessionFormat {
				t.Fatalf("tmux args %v", args)
			}
			return []byte("work__SHINPHONY_FIELD__1__SHINPHONY_FIELD__2__SHINPHONY_FIELD__$1__SHINPHONY_FIELD__42__SHINPHONY_FIELD__100__SHINPHONY_FIELD__/tmp")
		}
		return nil // screen with no sessions
	}
	if err := writeSessions(&out, find, run); err != nil {
		t.Fatal(err)
	}
	want := sessionsHeader + "\n" +
		"__SHINPHONY_REMOTE_TMUX__\n__SHINPHONY_AVAILABLE__\n" +
		"work__SHINPHONY_FIELD__1__SHINPHONY_FIELD__2__SHINPHONY_FIELD__$1__SHINPHONY_FIELD__42__SHINPHONY_FIELD__100__SHINPHONY_FIELD__/tmp\n" +
		"__SHINPHONY_REMOTE_ZELLIJ__\n" +
		"__SHINPHONY_REMOTE_SCREEN__\n__SHINPHONY_AVAILABLE__\n" +
		"__SHINPHONY_REMOTE_BYOBU__\n"
	if out.String() != want {
		t.Fatalf("got\n%s\nwant\n%s", out.String(), want)
	}
}

// Non-interactive SSH: PATH lacks the install directory (Mac mini, 1.0.7).
func TestFindToolFallsBackWhenPathLacksTool(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(bin, "shinphony-test-tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	missing := func(string) (string, error) { return "", errors.New("not found") }
	if got := findTool("shinphony-test-tool", missing, home); got != tool {
		t.Fatalf("got %q want %q", got, tool)
	}
	if got := findTool("shinphony-absent-tool", missing, home); got != "" {
		t.Fatalf("absent tool resolved to %q", got)
	}
	if err := os.Chmod(tool, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := findTool("shinphony-test-tool", missing, home); got != "" {
		t.Fatalf("non-executable file resolved to %q", got)
	}
	found := func(string) (string, error) { return "/on/path/tool", nil }
	if got := findTool("x", found, home); got != "/on/path/tool" {
		t.Fatalf("PATH result not preferred: %q", got)
	}
}

func TestSessionsCommandIsAcceptedByCLI(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `args[0] == "sessions"`) {
		t.Fatal("sessions command is not dispatched")
	}
}
