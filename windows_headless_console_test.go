package main

// TF 161: the scheduled task started the console-subsystem Hook directly, so
// Windows opened a black console window at logon and on every start. The task
// now runs it under `conhost.exe --headless` where Windows supports that, and
// otherwise falls back to the direct executable (which closes its own console in
// `supervise`/`serve`).

import (
	"strings"
	"testing"
)

func TestWindowsHeadlessConsoleSupported(t *testing.T) {
	// conhost.exe --headless arrives with Windows 10 21H2 (build 19044) and is
	// in Windows 11. Older builds get the fallback.
	cases := []struct {
		build uint32
		want  bool
	}{
		{0, false},
		{19041, false},
		{19043, false},
		{19044, true},
		{19045, true},
		{22000, true},
		{22631, true},
	}
	for _, c := range cases {
		if got := windowsHeadlessConsoleSupported(c.build); got != c.want {
			t.Errorf("windowsHeadlessConsoleSupported(%d) = %v, want %v", c.build, got, c.want)
		}
	}
}

func TestWindowsTaskActionIsHeadlessWhenSupported(t *testing.T) {
	const (
		exe       = `C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe`
		quotedExe = `"C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe"`
		arguments = `--state-dir C:\Users\you\.shinphony-agent --credentials-dir C:\Users\you\.shinphony-notify supervise`
		conhost   = `C:\Windows\System32\conhost.exe`
	)
	headless := windowsTaskActionFor(exe, quotedExe, arguments, conhost, true)
	if headless.Execute != conhost {
		t.Fatalf("headless Execute = %q, want conhost %q", headless.Execute, conhost)
	}
	want := "--headless " + quotedExe + " " + arguments
	if headless.Arguments != want {
		t.Fatalf("headless Arguments = %q, want %q", headless.Arguments, want)
	}
	// The task is still recognized as ours by the Hook it runs, in either form.
	if headless.Program != exe || headless.Conhost != conhost {
		t.Fatalf("headless action = %+v, want Program %q and Conhost %q", headless, exe, conhost)
	}

	for _, c := range []struct {
		name     string
		conhost  string
		headless bool
	}{
		{"older Windows", conhost, false},
		{"no conhost on disk", "", true},
	} {
		action := windowsTaskActionFor(exe, quotedExe, arguments, c.conhost, c.headless)
		if action.Execute != exe {
			t.Fatalf("%s: Execute = %q, want the Hook %q", c.name, action.Execute, exe)
		}
		if action.Arguments != arguments {
			t.Fatalf("%s: Arguments = %q, want %q", c.name, action.Arguments, arguments)
		}
	}
	// The direct form never carries the conhost marker, so a task that already
	// runs the bare exe is not treated as pre-TF 161 work to re-register.
	if direct := windowsTaskActionFor(exe, quotedExe, arguments, conhost, false); direct.Conhost != "" {
		t.Fatalf("direct action names conhost %q", direct.Conhost)
	}
}

func TestWindowsHeadlessArgumentsKeepTheHookArgumentsIntact(t *testing.T) {
	const (
		exe     = `C:\Users\First Last\.shinphony-agent\shinphony-hook-abc.exe`
		quoted  = `"C:\Users\First Last\.shinphony-agent\shinphony-hook-abc.exe"`
		conhost = `C:\Windows\System32\conhost.exe`
	)
	action := windowsTaskActionFor(exe, quoted, `--state-dir "C:\Users\First Last\.shinphony-agent" supervise`, conhost, true)
	if !strings.HasPrefix(action.Arguments, "--headless ") {
		t.Fatalf("Arguments = %q, want the --headless prefix", action.Arguments)
	}
	if !strings.HasSuffix(action.Arguments, `--state-dir "C:\Users\First Last\.shinphony-agent" supervise`) {
		t.Fatalf("Arguments = %q, want the Hook's own arguments last", action.Arguments)
	}
	if strings.Count(action.Arguments, quoted) != 1 {
		t.Fatalf("Arguments = %q, want the quoted Hook exactly once", action.Arguments)
	}
}
