//go:build darwin || linux

package main

// The Unix parts of address detection: the routing table, the bundle paths and
// the interface names to skip. The candidate list itself is in
// ssh_pair_address.go.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// The macOS app bundles ship the CLIs outside PATH.
const (
	sshPairNetBirdBundle   = "/Applications/NetBird.app/Contents/MacOS/netbird"
	sshPairTailscaleBundle = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
)

var (
	sshPairNetBirdInterface   = sshPairTunnelInterface("wt0", "utun*")
	sshPairTailscaleInterface = sshPairTunnelInterface("tailscale0", "utun*")
)

// sshPairVirtualInterface matches interfaces a phone cannot reach: container
// networks, VM bridges and macOS Internet Sharing. Their RFC 1918 addresses
// would otherwise fill the list.
func sshPairVirtualInterface(name string) bool {
	for _, prefix := range []string{
		"docker", "br-", "veth", "virbr", "cni", "flannel", "cali",
		"vmnet", "vboxnet", "bridge",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// systemSSHPairDefaultInterface asks the routing table which interface carries
// the default route, so the LAN list starts with the address a phone on the
// same network will actually reach.
func systemSSHPairDefaultInterface() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sshPairProbeTimeout)
	defer cancel()
	if runtime.GOOS == "darwin" {
		raw, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "default").Output()
		if err != nil {
			return "", err
		}
		return parseSSHPairDarwinDefaultRoute(raw)
	}
	ipCommand := "ip"
	if path, err := exec.LookPath("ip"); err == nil {
		ipCommand = path
	} else if _, statErr := os.Stat("/sbin/ip"); statErr == nil {
		ipCommand = "/sbin/ip"
	}
	raw, err := exec.CommandContext(ctx, ipCommand, "route", "show", "default").Output()
	if err != nil {
		return "", err
	}
	return parseSSHPairLinuxDefaultRoute(raw)
}

// parseSSHPairDarwinDefaultRoute reads the "interface: en0" line of
// `route -n get default`.
func parseSSHPairDarwinDefaultRoute(raw []byte) (string, error) {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "interface:" && validSSHPairInterfaceName(fields[1]) {
			return fields[1], nil
		}
	}
	return "", errors.New("ssh_pair_default_route_unavailable")
}

// parseSSHPairLinuxDefaultRoute reads the "dev en0" token of the first
// `ip route show default` line.
func parseSSHPairLinuxDefaultRoute(raw []byte) (string, error) {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" && validSSHPairInterfaceName(fields[i+1]) {
				return fields[i+1], nil
			}
		}
	}
	return "", errors.New("ssh_pair_default_route_unavailable")
}
