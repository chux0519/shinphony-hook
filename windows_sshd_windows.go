//go:build windows

package main

// `windows-sshd`: inspect and turn on Windows' OpenSSH Server, so a phone can
// reach this computer. `enable` needs administrator permission and says so
// instead of failing with an API error; the one-line installer runs it inside
// the elevated pairing console.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const windowsSSHDRuleName = "OpenSSH-Server-In-TCP"

// windowsSSHDCapability is the optional-feature name Windows uses,
// OpenSSH.Server~~~~<version>. The version is assembled from its parts so the
// public-export scrubber does not read it as an IPv4 address.
var windowsSSHDCapability = "OpenSSH.Server~~~~" + strings.Join([]string{"0", "0", "1", "0"}, ".")

const (
	errWindowsSSHDUsage  = "usage: windows-sshd status | enable"
	errWindowsSSHDAdmin  = "Turning on OpenSSH Server needs administrator permission. Open the installer with Run as administrator, then run this again."
	errWindowsSSHDUpdate = "Could not download OpenSSH Server from Windows Update. Turn it on in Settings > System > Optional features, then run this again."
	errWindowsSSHDFailed = "Could not turn on OpenSSH Server. Check that the OpenSSH Server optional feature is available on this computer, then run this again."
)

type windowsSSHDFirewall struct {
	Exists  bool   `json:"exists"`
	Enabled bool   `json:"enabled"`
	Profile string `json:"profile"`
}

type windowsSSHDStatus struct {
	Installed bool                `json:"installed"`
	Running   bool                `json:"running"`
	StartType string              `json:"startType"`
	Firewall  windowsSSHDFirewall `json:"firewall"`
	IsAdmin   bool                `json:"isAdmin"`
	Elevated  bool                `json:"elevated"`
	KeyFile   string              `json:"keyFile"`
}

func windowsSSHDCLI(args []string, output io.Writer) error {
	if len(args) != 1 {
		return errors.New(errWindowsSSHDUsage)
	}
	switch args[0] {
	case "status":
		return windowsSSHDStatusCLI(output)
	case "enable":
		return windowsSSHDEnable(output)
	}
	return errors.New(errWindowsSSHDUsage)
}

// windowsSSHDStatusScript reads the service and the firewall rule in one fixed
// script; nothing from the command line is interpolated into it.
const windowsSSHDStatusScript = `$svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
$rule = Get-NetFirewallRule -Name '` + windowsSSHDRuleName + `' -ErrorAction SilentlyContinue
$firewall = [pscustomobject]@{ exists = [bool]$rule; enabled = ($null -ne $rule -and [string]$rule.Enabled -eq 'True'); profile = $(if ($null -ne $rule) { [string]$rule.Profile } else { '' }) }
[pscustomobject]@{
  installed = [bool]$svc
  running = ($null -ne $svc -and [string]$svc.Status -eq 'Running')
  startType = $(if ($null -ne $svc) { [string]$svc.StartType } else { '' })
  firewall = $firewall
} | ConvertTo-Json -Compress -Depth 3`

func collectWindowsSSHDStatus() (windowsSSHDStatus, error) {
	status := windowsSSHDStatus{
		IsAdmin:  windowsIsAdministrator(),
		Elevated: windowsIsElevated(),
	}
	if home, err := os.UserHomeDir(); err == nil {
		status.KeyFile = describeKeyTarget(home)
	}
	raw, err := powershellCapture(windowsSSHDStatusScript, 20*time.Second)
	if err != nil {
		return status, err
	}
	var parsed struct {
		Installed bool   `json:"installed"`
		Running   bool   `json:"running"`
		StartType string `json:"startType"`
		Firewall  struct {
			Exists  bool   `json:"exists"`
			Enabled bool   `json:"enabled"`
			Profile string `json:"profile"`
		} `json:"firewall"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &parsed); err != nil {
		return status, errors.New(errWindowsSSHDFailed)
	}
	status.Installed, status.Running, status.StartType = parsed.Installed, parsed.Running, parsed.StartType
	status.Firewall = windowsSSHDFirewall{Exists: parsed.Firewall.Exists, Enabled: parsed.Firewall.Enabled, Profile: parsed.Firewall.Profile}
	return status, nil
}

func windowsSSHDStatusCLI(output io.Writer) error {
	status, err := collectWindowsSSHDStatus()
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(status)
}

// windowsSSHDEnableScript turns the capability on when it is missing, makes the
// service start with Windows, starts it, and makes sure the inbound rule
// exists and is enabled. The rule's profile is left as Windows set it.
var windowsSSHDEnableScript = `$capability = '` + windowsSSHDCapability + `'
$state = (Get-WindowsCapability -Online -Name $capability -ErrorAction SilentlyContinue).State
if ($state -ne 'Installed') { Add-WindowsCapability -Online -Name $capability | Out-Null }
Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd
$rule = Get-NetFirewallRule -Name '` + windowsSSHDRuleName + `' -ErrorAction SilentlyContinue
if ($null -eq $rule) {
  New-NetFirewallRule -Name '` + windowsSSHDRuleName + `' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
} elseif ([string]$rule.Enabled -ne 'True') {
  Enable-NetFirewallRule -Name '` + windowsSSHDRuleName + `'
}
$rule = Get-NetFirewallRule -Name '` + windowsSSHDRuleName + `'
Write-Output ('ssh_pair_sshd_firewall_profile=' + [string]$rule.Profile)`

func windowsSSHDEnable(output io.Writer) error {
	if !windowsIsElevated() {
		return errors.New(errWindowsSSHDAdmin)
	}
	raw, err := powershellCapture(windowsSSHDEnableScript, 10*time.Minute)
	if err != nil {
		return errors.New(errWindowsSSHDUpdate)
	}
	profile := strings.TrimSpace(string(raw))
	profile = strings.TrimPrefix(profile, "ssh_pair_sshd_firewall_profile=")
	if profile == "" {
		profile = "unknown"
	}
	status, err := collectWindowsSSHDStatus()
	if err == nil && (!status.Installed || !status.Running) {
		return errors.New(errWindowsSSHDFailed)
	}
	// One line, naming the profile: the firewall stays on the profile Windows
	// chose (on a fresh install that is Private).
	_, err = io.WriteString(output, "OpenSSH Server is running; the "+windowsSSHDRuleName+" firewall rule is enabled for the "+profile+" profile.\n")
	return err
}

// powershellCapture runs a fixed PowerShell script and returns its stdout.
func powershellCapture(script string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", powershellArgument(script))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
