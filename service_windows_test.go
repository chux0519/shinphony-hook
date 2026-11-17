//go:build windows

package main

// TF 159: pairing on an administrator account printed "Could not start
// Shinphony Hook; set it up from Shinphony." with no way to know which step
// stopped. The task install is now one fixed script whose stages report
// themselves, and a task this account already registered for the same binary is
// started instead of refused (the state an interrupted pairing leaves behind).
// These tests pin the script's shape and the mapping from its report.
//
// TF 161: the script also decides between starting the existing task and
// re-registering it. A task registered before TF 161 runs the bare Hook
// executable, which opens a console window; it is ours, so it is replaced with
// the headless action instead of being started as it is.

import (
	"errors"
	"strings"
	"testing"
)

const (
	fixtureHeadlessConhost = `C:\Windows\System32\conhost.exe`
)

func fixtureTaskScript(t *testing.T) string {
	t.Helper()
	action := windowsTaskActionFor(
		`C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe`,
		`"C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe"`,
		`--state-dir C:\Users\you\.shinphony-agent --credentials-dir C:\Users\you\.shinphony-notify supervise`,
		fixtureHeadlessConhost,
		true,
	)
	return windowsServiceTaskScript("net.potafree.shinphony.agent.0123456789ab", action)
}

func TestWindowsServiceTaskScriptIsFixedAndQuoted(t *testing.T) {
	script := fixtureTaskScript(t)
	for _, want := range []string{
		// One task name per state directory, and the same executable we would install.
		`$name = 'net.potafree.shinphony.agent.0123456789ab'`,
		`$exe = 'C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe'`,
		`$execute = 'C:\Windows\System32\conhost.exe'`,
		`$arguments = '--headless "C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe" --state-dir C:\Users\you\.shinphony-agent --credentials-dir C:\Users\you\.shinphony-notify supervise'`,
		`$conhost = 'C:\Windows\System32\conhost.exe'`,
		// An existing task is only reused when it runs our Hook, in either form.
		`$ours = ($actionExe -eq $exe) -or (($conhost -ne '') -and ($actionExe -eq $conhost) -and $actionArgs.Contains($exe))`,
		`if (-not $ours) { throw 'shinphony_service_other_binary' }`,
		`try { Start-ScheduledTask -TaskName $name -ErrorAction Stop } catch { throw ('shinphony_service_start_failed: ' + $_.Exception.Message) }`,
		// Registration names itself too: Windows may refuse it without elevation.
		`try { Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null } catch { throw ('shinphony_service_task_failed: ' + $_.Exception.Message) }`,
		// The action is the one we built, not the bare exe.
		`$action = New-ScheduledTaskAction -Execute $execute -Argument $arguments`,
		// The task runs as the user who paired, interactively, without elevation.
		`New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited`,
		`Write-Output 'shinphony_service_registered'`,
		`Write-Output 'shinphony_service_started_existing'`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script is missing %q:\n%s", want, script)
		}
	}
	// No script text may be interpolated from the command line: the whole file
	// is one fixed template around single-quoted literals.
	// Every throw names a fixed step, so the report maps to it.
	throws := strings.Count(script, "throw ")
	if throws == 0 || throws != strings.Count(script, "throw 'shinphony_service_")+strings.Count(script, "throw ('shinphony_service_") {
		t.Fatalf("every throw must name a fixed shinphony_service_ step:\n%s", script)
	}
	if !strings.HasPrefix(script, "$ErrorActionPreference = 'Stop'") {
		t.Fatal("a failing step must stop the script")
	}
}

func TestWindowsServiceTaskScriptReRegistersTheBareExeForm(t *testing.T) {
	script := fixtureTaskScript(t)
	for _, want := range []string{
		// An existing task whose action already is this one is started, not
		// rewritten: that is the state an interrupted pairing leaves behind.
		`if (($actionExe -eq $execute) -and ($actionArgs -eq $arguments)) {`,
		// Anything else that runs our Hook (the bare exe of a task registered
		// before TF 161, or a stale argument list) is re-registered below.
		`$actionExe = [string]$existing.Actions[0].Execute`,
		`$actionArgs = [string]$existing.Actions[0].Arguments`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script is missing %q:\n%s", want, script)
		}
	}
	// Starting the existing task must happen inside the identity branch, and
	// registering outside it: the bare-exe task must never be started as it is.
	identity := strings.Index(script, `if (($actionExe -eq $execute) -and ($actionArgs -eq $arguments)) {`)
	started := strings.Index(script, `Write-Output 'shinphony_service_started_existing'`)
	registered := strings.Index(script, `Write-Output 'shinphony_service_registered'`)
	if identity < 0 || started < identity || registered < started {
		t.Fatalf("the script must start an identical task first and register otherwise:\n%s", script)
	}
	if strings.Count(script, "Register-ScheduledTask") != 1 {
		t.Fatalf("registration must happen in exactly one place:\n%s", script)
	}
}

func TestWindowsServiceTaskScriptWithoutHeadlessRunsTheBareExe(t *testing.T) {
	// The fallback keeps today's action so an older Windows runs as before.
	action := windowsTaskActionFor(
		`C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe`,
		`C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe`,
		`--state-dir C:\Users\you\.shinphony-agent supervise`,
		fixtureHeadlessConhost,
		false,
	)
	script := windowsServiceTaskScript("net.potafree.shinphony.agent.0123456789ab", action)
	if !strings.Contains(script, `$execute = 'C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe'`) {
		t.Fatalf("fallback must execute the Hook itself:\n%s", script)
	}
	if !strings.Contains(script, `$conhost = ''`) {
		t.Fatalf("fallback must not name conhost as a way to run our Hook:\n%s", script)
	}
	if strings.Contains(script, "--headless") {
		t.Fatalf("fallback must not use --headless:\n%s", script)
	}
}

func TestWindowsServiceTaskReportMapsToTheFailedStep(t *testing.T) {
	cases := []struct {
		out  string
		want error
	}{
		{"shinphony_service_other_binary", errServiceTaskOtherBinary},
		{"shinphony_service_start_failed: Access is denied", errServiceTaskStart},
		{"shinphony_service_task_failed: Access is denied", errServiceTaskNeedsAdmin},
		{"shinphony_service_task_failed: (0x80070005)", errServiceTaskNeedsAdmin},
		{"shinphony_service_task_failed: The parameter is incorrect.", errServiceTaskRegister},
		{"", errServiceTaskRegister},
	}
	for _, c := range cases {
		if got := serviceTaskError(c.out); !errors.Is(got, c.want) {
			t.Fatalf("serviceTaskError(%q) = %v, want %v", c.out, got, c.want)
		}
	}
}
func TestWindowsServiceTaskCurrentScriptOnlyReads(t *testing.T) {
	// ensure-service on a running service of this binary asks whether the task
	// already has the current action; a bare-exe task registered before TF 161
	// is not "current", so it is re-registered by install.
	action := windowsTaskActionFor(
		`C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe`,
		`"C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe"`,
		`--state-dir C:\Users\you\.shinphony-agent supervise`,
		fixtureHeadlessConhost,
		true,
	)
	script := windowsServiceTaskCurrentScript("net.potafree.shinphony.agent.0123456789ab", action)
	for _, want := range []string{
		`$name = 'net.potafree.shinphony.agent.0123456789ab'`,
		`$execute = 'C:\Windows\System32\conhost.exe'`,
		`$arguments = '--headless "C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe" --state-dir C:\Users\you\.shinphony-agent supervise'`,
		`([string]$existing.Actions[0].Execute -eq $execute) -and ([string]$existing.Actions[0].Arguments -eq $arguments)`,
		`Write-Output 'shinphony_service_current'`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script is missing %q:\n%s", want, script)
		}
	}
	for _, never := range []string{"Register-ScheduledTask", "Start-ScheduledTask", "Stop-ScheduledTask", "Unregister-ScheduledTask"} {
		if strings.Contains(script, never) {
			t.Fatalf("the check must only read, found %q:\n%s", never, script)
		}
	}
}
