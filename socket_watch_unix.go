//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// socketWatchInterval is a variable so tests can shorten it.
var socketWatchInterval = time.Minute

// watchSocket guards the /tmp socket. macOS's periodic cleanup (and tmp
// reapers on Linux) delete entries in /tmp that have not been touched for a
// few days; the listener keeps running but nobody can connect, so `status`
// reports service_unavailable. Each tick refreshes the directory's and the
// socket's times so they are never "old", and if the socket was removed or
// replaced anyway the returned channel yields an error: serve exits non-zero
// and the service manager (launchd KeepAlive / systemd Restart) starts a
// fresh listener.
func watchSocket(ctx context.Context, dir string) <-chan error {
	out := make(chan error, 1)
	parents, err := socketDirs(dir)
	if err != nil {
		return out
	}
	parent := parents[len(parents)-1]
	socket := filepath.Join(parent, "agent.sock")
	initial, err := os.Lstat(socket)
	if err != nil {
		return out
	}
	go func() {
		t := time.NewTicker(socketWatchInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			now := time.Now()
			_ = os.Chtimes(parent, now, now)
			s, err := os.Lstat(socket)
			if err != nil || !os.SameFile(initial, s) {
				out <- errors.New("socket_removed")
				return
			}
			_ = os.Chtimes(socket, now, now)
		}
	}()
	return out
}
