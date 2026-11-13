package main

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// Separate lock handles model concurrent installers targeting one state dir.
// Keep the winning handle alive until every contender has attempted entry.
func TestLifecycleLockConcurrentAndReacquire(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "lifecycle")
	if err := prepareDir(dir); err != nil {
		t.Fatal(err)
	}
	var entered atomic.Int32
	var attempts sync.WaitGroup
	var workers sync.WaitGroup
	start, release := make(chan struct{}), make(chan struct{})
	for i := 0; i < 32; i++ {
		attempts.Add(1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			unlock, err := lockDir(dir)
			if err == nil {
				entered.Add(1)
			}
			attempts.Done()
			if err == nil {
				<-release
				unlock()
			}
		}()
	}
	close(start)
	attempts.Wait()
	close(release)
	workers.Wait()
	if got := entered.Load(); got != 1 {
		t.Fatalf("expected one lifecycle owner, got %d", got)
	}
	unlock, err := lockDir(dir)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	unlock()
}
