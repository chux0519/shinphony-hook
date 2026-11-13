//go:build !windows

package main

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestWatchSocketReportsRemovedSocket(t *testing.T) {
	old := socketWatchInterval
	socketWatchInterval = 20 * time.Millisecond
	defer func() { socketWatchInterval = old }()
	dir := t.TempDir()
	ln, err := listenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	parents, _ := socketDirs(dir)
	parent := parents[len(parents)-1]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gone := watchSocket(ctx, dir)
	select {
	case err := <-gone:
		t.Fatalf("watchdog fired while the socket exists: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	// Simulate the /tmp reaper.
	if err := os.RemoveAll(parent); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-gone:
		if err == nil || err.Error() != "socket_removed" {
			t.Fatalf("want socket_removed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not report the removed socket")
	}
}

func TestWatchSocketRefreshesTimes(t *testing.T) {
	old := socketWatchInterval
	socketWatchInterval = 20 * time.Millisecond
	defer func() { socketWatchInterval = old }()
	dir := t.TempDir()
	ln, err := listenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	parents, _ := socketDirs(dir)
	parent := parents[len(parents)-1]
	stale := time.Now().Add(-96 * time.Hour)
	if err := os.Chtimes(parent, stale, stale); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchSocket(ctx, dir)
	time.Sleep(150 * time.Millisecond)
	s, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(s.ModTime()) > time.Minute {
		t.Fatalf("socket directory still stale: %v", s.ModTime())
	}
}
