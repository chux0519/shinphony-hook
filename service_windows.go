package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

func psLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// powershellArgument is the -EncodedCommand value for a fixed script: PowerShell
// is started with UTF-16 script text, never with interpolated command-line
// arguments.
func powershellArgument(script string) string {
	words := utf16.Encode([]rune("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; " + script))
	raw := make([]byte, 2*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint16(raw[2*i:], w)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
func powershell(script string) error {
	return serviceCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", powershellArgument(script))
}

// The per-user task's fixed script. Every step names itself on stdout, so a
// failure is reported as the step that failed (TF 159: the pairing warning only
// said "Could not start Shinphony Hook"). A task this account already
// registered for the very same binary is started instead of refused: that is
// the state a pairing leaves behind when its start was interrupted.
const windowsServiceTaskScriptHead = `$ErrorActionPreference = 'Stop'
$name = `

const windowsServiceTaskScriptTail = `
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$existing = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if ($null -ne $existing) {
  if ([string]$existing.Actions[0].Execute -ne $exe) { throw 'shinphony_service_other_binary' }
  try { Start-ScheduledTask -TaskName $name -ErrorAction Stop } catch { throw ('shinphony_service_start_failed: ' + $_.Exception.Message) }
  Write-Output 'shinphony_service_started_existing'
  return
}
$action = New-ScheduledTaskAction -Execute $exe -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
try { Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null } catch { throw ('shinphony_service_task_failed: ' + $_.Exception.Message) }
try { Start-ScheduledTask -TaskName $name -ErrorAction Stop } catch { throw ('shinphony_service_start_failed: ' + $_.Exception.Message) }
Write-Output 'shinphony_service_registered'`

// windowsServiceTaskScript is the whole fixed script for one task.
func windowsServiceTaskScript(name, exe, arguments string) string {
	return windowsServiceTaskScriptHead + psLiteral(name) + `; $exe = ` + psLiteral(exe) +
		`; $arguments = ` + psLiteral(arguments) + windowsServiceTaskScriptTail
}

// serviceTaskError maps what the script reported to the step that failed. The
// output itself is never shown: it can carry paths (support-safe rule).
func serviceTaskError(out string) error {
	switch {
	case strings.Contains(out, "shinphony_service_other_binary"):
		return errServiceTaskOtherBinary
	case strings.Contains(out, "shinphony_service_start_failed"):
		return errServiceTaskStart
	case strings.Contains(out, "shinphony_service_task_failed"):
		// Registration is the one step Windows may refuse without elevation.
		if strings.Contains(out, "Access is denied") || strings.Contains(out, "0x80070005") {
			return errServiceTaskNeedsAdmin
		}
		return errServiceTaskRegister
	}
	return errServiceTaskRegister
}

// powershellReported runs a fixed script and returns its combined output, for
// scripts whose stages report themselves.
func powershellReported(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", powershellArgument(script))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func installService(dir, creds string) error {
	exe, err := serviceExecutable(dir)
	if err != nil {
		return err
	}
	arguments := "--state-dir " + syscall.EscapeArg(dir) + " --credentials-dir " + syscall.EscapeArg(creds) + " supervise"
	out, err := powershellReported(windowsServiceTaskScript(serviceName(dir), exe, arguments))
	if err != nil {
		return serviceTaskError(out)
	}
	if err = awaitService(dir); err != nil {
		return err
	}
	fmt.Println(`{"installed":true,"scope":"logged-in-user","service":"` + serviceName(dir) + `"}`)
	return nil
}
func uninstallService(dir string) error {
	if err := powershell(`$name=` + psLiteral(serviceName(dir)) + `; $task=Get-ScheduledTask -TaskName $name -ErrorAction Stop; $owner=$task.Principal.UserId; if($owner -notlike 'S-1-*'){$owner=([System.Security.Principal.NTAccount]::new($owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value}; if($owner -ne [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'owner_mismatch'}; Stop-ScheduledTask -TaskName $name; Unregister-ScheduledTask -TaskName $name -Confirm:$false`); err != nil {
		return err
	}
	return awaitStopped(dir)
}
