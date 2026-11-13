package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdateProgressReadOnlyAndStale(t *testing.T) {
	dir := privateTemp(t)
	if got := updateProgress(dir); got["state"] != "unknown" {
		t.Fatal(got)
	}
	ud := filepath.Join(dir, "updates")
	if _, err := os.Stat(ud); !os.IsNotExist(err) {
		t.Fatal("status created update directory")
	}
	if err := prepareDir(ud); err != nil {
		t.Fatal(err)
	}
	if err := saveUpdateState(ud, updateState{State: "downloading", Sequence: 7}); err != nil {
		t.Fatal(err)
	}
	got := updateProgress(dir)
	if got["state"] != "downloading" || got["stale"] != false {
		t.Fatal(got)
	}
	if err := os.WriteFile(filepath.Join(ud, "state.json"), []byte(`{"state":"applying","sequence":7,"updated":1,"nextCheck":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := updateProgress(dir); got["stale"] != true {
		t.Fatal(got)
	}
	if err := saveUpdateState(ud, updateState{State: "healthy", NextCheck: time.Now().Unix() + 3600}); err != nil {
		t.Fatal(err)
	}
	if got := updateProgress(dir); got["stale"] != false {
		t.Fatal(got)
	}
}
