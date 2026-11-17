package main

// TF 161 fallback: on Windows without `conhost.exe --headless` the task runs
// the Hook directly and `supervise`/`serve` close the console Windows opened
// for them, but never a console shared with the shell someone ran them from.

import "testing"

func TestConsoleOwnedAlone(t *testing.T) {
	for count, want := range map[int]bool{0: false, 1: true, 2: false, 3: false} {
		if got := consoleOwnedAlone(count); got != want {
			t.Errorf("consoleOwnedAlone(%d) = %v, want %v", count, got, want)
		}
	}
}
