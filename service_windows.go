package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
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
  $actionExe = [string]$existing.Actions[0].Execute
  $actionArgs = [string]$existing.Actions[0].Arguments
  $ours = ($actionExe -eq $exe) -or (($conhost -ne '') -and ($actionExe -eq $conhost) -and $actionArgs.Contains($exe))
  if (-not $ours) { throw 'shinphony_service_other_binary' }
  if (($actionExe -eq $execute) -and ($actionArgs -eq $arguments)) {
    try { Start-ScheduledTask -TaskName $name -ErrorAction Stop } catch { throw ('shinphony_service_start_failed: ' + $_.Exception.Message) }
    Write-Output 'shinphony_service_started_existing'
    return
  }
  # Our Hook in an older form (the bare exe opens a console window, TF 161):
  # stop it and register the current action over it.
  Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
}
$action = New-ScheduledTaskAction -Execute $execute -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
try { Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null } catch { throw ('shinphony_service_task_failed: ' + $_.Exception.Message) }
try { Start-ScheduledTask -TaskName $name -ErrorAction Stop } catch { throw ('shinphony_service_start_failed: ' + $_.Exception.Message) }
Write-Output 'shinphony_service_registered'`

// windowsServiceTaskScript is the whole fixed script for one task. $exe is the
// Hook that identifies the task as ours; $execute/$arguments are the action to
// register; $conhost is set only for the headless form.
func windowsServiceTaskScript(name string, action windowsTaskAction) string {
	return windowsServiceTaskScriptHead + psLiteral(name) +
		`; $exe = ` + psLiteral(action.Program) +
		`; $execute = ` + psLiteral(action.Execute) +
		`; $arguments = ` + psLiteral(action.Arguments) +
		`; $conhost = ` + psLiteral(action.Conhost) + windowsServiceTaskScriptTail
}

// windowsConhostPath is %SystemRoot%\System32\conhost.exe when it exists.
func windowsConhostPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	path := filepath.Join(root, "System32", "conhost.exe")
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return path
}

// windowsServiceTaskAction is the task action for this computer: headless under
// conhost.exe when this Windows build supports it, else the Hook itself. The
// probe is one version call and one stat, done at install.
func windowsServiceTaskAction(exe, arguments string) windowsTaskAction {
	build := windows.RtlGetVersion().BuildNumber
	return windowsTaskActionFor(exe, `"`+exe+`"`, arguments, windowsConhostPath(), windowsHeadlessConsoleSupported(build))
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

// windowsServiceArguments are the Hook's own arguments in the task action.
func windowsServiceArguments(dir, creds string) string {
	return "--state-dir " + syscall.EscapeArg(dir) + " --credentials-dir " + syscall.EscapeArg(creds) + " supervise"
}

func installService(dir, creds string) error {
	exe, err := serviceExecutable(dir)
	if err != nil {
		return err
	}
	out, err := powershellReported(windowsServiceTaskScript(serviceName(dir), windowsServiceTaskAction(exe, windowsServiceArguments(dir, creds))))
	if err != nil {
		return serviceTaskError(out)
	}
	if err = awaitService(dir); err != nil {
		return err
	}
	fmt.Println(`{"installed":true,"scope":"logged-in-user","service":"` + serviceName(dir) + `"}`)
	return nil
}

// windowsServiceTaskCurrentScript reports whether the task already runs the
// current action. It only reads.
func windowsServiceTaskCurrentScript(name string, action windowsTaskAction) string {
	return `$name = ` + psLiteral(name) + `; $execute = ` + psLiteral(action.Execute) + `; $arguments = ` + psLiteral(action.Arguments) + `
$existing = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if (($null -ne $existing) -and ([string]$existing.Actions[0].Execute -eq $execute) -and ([string]$existing.Actions[0].Arguments -eq $arguments)) { Write-Output 'shinphony_service_current' }`
}

// refreshService re-registers a running service of this binary whose task still
// has an older action (TF 161: the bare exe, which opens a console window). A
// check that cannot run leaves the working service alone.
func refreshService(dir, creds, exe string) error {
	action := windowsServiceTaskAction(exe, windowsServiceArguments(dir, creds))
	out, err := powershellReported(windowsServiceTaskCurrentScript(serviceName(dir), action))
	if err != nil || strings.Contains(out, "shinphony_service_current") {
		fmtInstalled()
		return nil
	}
	return installService(dir, creds)
}

func uninstallService(dir string) error {
	if err := powershell(`$name=` + psLiteral(serviceName(dir)) + `; $task=Get-ScheduledTask -TaskName $name -ErrorAction Stop; $owner=$task.Principal.UserId; if($owner -notlike 'S-1-*'){$owner=([System.Security.Principal.NTAccount]::new($owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value}; if($owner -ne [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'owner_mismatch'}; Stop-ScheduledTask -TaskName $name; Unregister-ScheduledTask -TaskName $name -Confirm:$false`); err != nil {
		return err
	}
	return awaitStopped(dir)
}

// The background task runs as the user (never elevated), so the supervisor can
// leave its worker's last error in the state directory: the DACL, not the owner,
// decides that write, and the folder grants this account FullControl. That one
// file is how `install-service` turns a timeout into a step (TF 160).

// windowsServiceLogName is the worker's last-failure log inside the state folder.
const windowsServiceLogName = "service.log"

// windowsServiceLogLimit bounds both what is kept and what is read back.
const windowsServiceLogLimit = 8 * 1024

// tailBuffer keeps the last limit bytes written to it, so a supervisor that runs
// for hours does not grow with its worker's output.
type tailBuffer struct {
	buf   []byte
	limit int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.limit {
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-t.limit:]...)
	}
	return len(p), nil
}

// recordServiceLog replaces the log with the worker's last failure. It is a
// diagnostic, never state, so a write that fails is ignored.
func recordServiceLog(dir, detail string) {
	detail = strings.TrimSpace(strings.ReplaceAll(detail, "\r\n", "\n"))
	if len(detail) > windowsServiceLogLimit/2 {
		detail = detail[len(detail)-windowsServiceLogLimit/2:]
	}
	_ = os.WriteFile(filepath.Join(dir, windowsServiceLogName), []byte("worker_exit "+detail), 0600)
}

// windowsServiceLogText is the log's content, empty when there is none.
func windowsServiceLogText(dir string) string {
	file, err := os.Open(filepath.Join(dir, windowsServiceLogName))
	if err != nil {
		return ""
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, windowsServiceLogLimit))
	if err != nil {
		return ""
	}
	return string(data)
}

// windowsServiceLogSaysFolderUnsafe reports whether the worker itself rejected
// the state folder.
func windowsServiceLogSaysFolderUnsafe(dir string) bool {
	return strings.Contains(windowsServiceLogText(dir), unsafeStateDirectory)
}

// windowsFolderOwnerIsAdministrators reports whether the folder an elevated
// pairing leaves behind is still owned by BUILTIN\Administrators.
func windowsFolderOwnerIsAdministrators(dir string) bool {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	administrators, err := windowsAdministratorsSID()
	return err == nil && owner.Equals(administrators)
}

// windowsServiceFolderOwner is a variable so the mapping below can be tested for
// the folder an elevated pairing creates, without creating one here.
var windowsServiceFolderOwner = windowsFolderOwnerIsAdministrators

// serviceNotReadyHint explains a service that registered but never answered: the
// worker's own log says it rejected the folder, and the folder is owned by
// Administrators.
func serviceNotReadyHint(dir string) error {
	if !windowsServiceLogSaysFolderUnsafe(dir) || !windowsServiceFolderOwner(dir) {
		return nil
	}
	return errServiceFolderOwner
}
