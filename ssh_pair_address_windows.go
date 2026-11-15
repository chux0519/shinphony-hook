//go:build windows

package main

// The Windows parts of address detection: the default-route interface, the VPN
// install paths and the adapter names to skip. The candidate list itself is in
// ssh_pair_address.go.

import (
	"errors"
	"net"
	"strings"
)

// The default install locations; PATH is still probed first.
const (
	sshPairNetBirdBundle   = `C:\Program Files\NetBird\netbird.exe`
	sshPairTailscaleBundle = `C:\Program Files\Tailscale\tailscale.exe`
)

var (
	sshPairNetBirdInterface   = sshPairTunnelInterface("wt0*", "netbird*", "wintun*")
	sshPairTailscaleInterface = sshPairTunnelInterface("tailscale*")
)

// sshPairVirtualInterface matches adapters a phone cannot reach: Hyper-V and WSL
// switches, container and VM host networks, and loopback pseudo-adapters. Their
// RFC 1918 addresses would otherwise fill the list.
func sshPairVirtualInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{
		"vethernet", "default switch", "wsl", "docker", "loopback",
		"bluetooth", "vmware", "virtualbox", "vbox", "tap-", "npcap",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return strings.Contains(lower, "virtual") || strings.Contains(lower, "pseudo")
}

// systemSSHPairDefaultInterface names the interface Windows would route
// internet traffic through. A UDP connect sends no packet; it only asks the
// routing table for the source address, which is then matched to an adapter.
func systemSSHPairDefaultInterface() (string, error) {
	conn, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return "", errors.New("ssh_pair_default_route_unavailable")
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil || local.IP.IsUnspecified() {
		return "", errors.New("ssh_pair_default_route_unavailable")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", errors.New("ssh_pair_default_route_unavailable")
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ip, ok := sshPairParseIPv4(addr.String()); ok && ip.Equal(local.IP) {
				if !validSSHPairInterfaceName(iface.Name) {
					return "", errors.New("ssh_pair_default_route_unavailable")
				}
				return iface.Name, nil
			}
		}
	}
	return "", errors.New("ssh_pair_default_route_unavailable")
}
