//go:build windows

package main

// TF 159: pairing on an administrator account printed "Could not start
// Shinphony Hook; set it up from Shinphony." with no way to know which step
// stopped. The task install is now one fixed script whose stages report
// themselves, and a task this account already registered for the same binary is
// started instead of refused (the state an interrupted pairing leaves behind).
// These tests pin the script's shape and the mapping from its report.

import (
	"errors"
	"strings"
	"testing"
)

func fixtureTaskScript(t *testing.T) string {
	t.Helper()
	return windowsServiceTaskScript(
		"net.potafree.shinphony.agent.0123456789ab",
		`C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe`,
		`--state-dir C:\Users\you\.shinphony-agent --credentials-dir C:\Users\you\.shinphony-notify supervise`)
}

func TestWindowsServiceTaskScriptIsFixedAndQuoted(t *testing.T) {
	script := fixtureTaskScript(t)
	for _, want := range []string{
		// One task name per state directory, and the same executable we would install.
		`$name = 'net.potafree.shinphony.agent.0123456789ab'`,
		`$exe = 'C:\Users\you\.shinphony-agent\shinphony-hook-abc.exe'`,
		// An existing task is only reused when it is ours.
		`if ([string]$existing.Actions[0].Execute -ne $exe) { throw 'shinphony_service_other_binary' }`,
		`try { Start-ScheduledTask -TaskName $name -ErrorAction Stop } catch { throw ('shinphony_service_start_failed: ' + $_.Exception.Message) }`,
		// Registration names itself too: Windows may refuse it without elevation.
		`try { Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null } catch { throw ('shinphony_service_task_failed: ' + $_.Exception.Message) }`,
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
	if strings.Count(script, "throw '") != 3 {
		t.Fatalf("script throws in an unexpected number of places:\n%s", script)
	}
	if !strings.HasPrefix(script, "$ErrorActionPreference = 'Stop'") {
		t.Fatal("a failing step must stop the script")
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