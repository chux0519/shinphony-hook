package main

import (
	"context"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Environment can be filtered by Codex even in standalone mode. Only a pane's
// shell appearing in the actual process ancestry is evidence of ownership.
// Default tmux socket only: custom sockets without TMUX remain unavailable,
// never guessed from terminal titles, cwd, recent activity or other users.
func discoverTaskPane(ctx context.Context, pid int) (string, string) {
	ancestors := map[int]bool{}
	for n := 0; n < 24 && pid > 1; n++ {
		if ancestors[pid] {
			return "", ""
		}
		ancestors[pid] = true
		raw, err := commandOutput(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "ppid=")
		if err != nil {
			return "", ""
		}
		pid, err = strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return "", ""
		}
	}
	raw, err := tmuxOutput(ctx, "list-panes", "-a", "-F", "#{socket_path}\t#{pid}\t#{pane_id}\t#{pane_pid}")
	if err != nil {
		return "", ""
	}
	return matchTaskPane(raw, ancestors)
}

func matchTaskPane(raw string, ancestors map[int]bool) (string, string) {
	var socket, pane string
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		p := strings.Split(line, "\t")
		if len(p) != 4 || !filepath.IsAbs(p[0]) || len(p[0]) > 1024 ||
			!regexp.MustCompile(`^[0-9]+$`).MatchString(p[1]) ||
			!regexp.MustCompile(`^%[0-9]+$`).MatchString(p[2]) {
			return "", ""
		}
		pid, err := strconv.Atoi(p[3])
		if err != nil || pid <= 1 {
			return "", ""
		}
		if !ancestors[pid] {
			continue
		}
		key := p[0] + "\t" + p[1] + "\t" + p[2]
		if seen[key] {
			continue
		} // Linked windows may list the same pane twice.
		if pane != "" {
			return "", ""
		}
		seen[key] = true
		socket, pane = p[0]+","+p[1]+",0", p[2]
	}
	return socket, pane
}
