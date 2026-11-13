package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unicode/utf16"
)

func psLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func powershell(script string) error {
	words := utf16.Encode([]rune("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; " + script))
	raw := make([]byte, 2*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint16(raw[2*i:], w)
	}
	return serviceCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
}
func installService(dir, creds string) error {
	exe, err := serviceExecutable(dir)
	if err != nil {
		return err
	}
	arguments := "--state-dir " + syscall.EscapeArg(dir) + " --credentials-dir " + syscall.EscapeArg(creds) + " supervise"
	script := `$name=` + psLiteral(serviceName(dir)) + `; if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'service_already_exists'}; $user=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $action=New-ScheduledTaskAction -Execute ` + psLiteral(exe) + ` -Argument ` + psLiteral(arguments) + `; $trigger=New-ScheduledTaskTrigger -AtLogOn -User $user; $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited; $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew; Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null; Start-ScheduledTask -TaskName $name`
	if err = powershell(script); err != nil {
		return err
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
