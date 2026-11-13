//go:build darwin || linux

package main

// VPN and network address candidates for `pair` (iteration
// iter-20261113-1700-hook-vpn-opensource, section A).
//
// Users on NetBird or Tailscale should not have to look up an IP: detection
// asks the CLIs, falls back to their tunnel interfaces, and lists the LAN and
// mDNS names as well. Detection is best effort and never fatal; the pairing
// prompt has a default either way.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Labels printed next to an address in the prompt.
const (
	sshPairLabelNetBird   = "NetBird"
	sshPairLabelTailscale = "Tailscale"
	sshPairLabelLAN       = "LAN"
	sshPairLabelSameWiFi  = "Same Wi-Fi"
)

// sshPairAddressLimit caps the numbered list at six entries.
const sshPairAddressLimit = 6

// sshPairLANLimit caps the LAN entries: more than two are noise (a home
// network plus a second network is enough to choose from).
const sshPairLANLimit = 2

// sshPairProbeTimeout bounds each detection probe, so a hung VPN CLI cannot
// delay the pairing.
const sshPairProbeTimeout = 2 * time.Second

// The macOS app bundles ship the CLIs outside PATH.
const (
	sshPairNetBirdBundle   = "/Applications/NetBird.app/Contents/MacOS/netbird"
	sshPairTailscaleBundle = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
)

const sshPairAddressQuestion = "How will your phone reach this computer?"

// sshPairAddressCandidate is one address the phone could use, with the source
// label shown in the prompt.
type sshPairAddressCandidate struct {
	Address string
	Label   string
}

// sshPairInterface is the part of net.Interface detection reads, so tests can
// pass fake interfaces instead of the machine's.
type sshPairInterface struct {
	Name     string
	Up       bool
	Loopback bool
	// Addrs are the interface addresses as net.Addr.String prints them,
	// e.g. "192.0.2.10/24" or "fe80::1%en0/64".
	Addrs []string
}

// sshPairProbe is the environment detection reads. Every field is a function
// so tests replace the whole environment with fakes.
type sshPairProbe struct {
	command      func(ctx context.Context, path string, args ...string) ([]byte, error)
	lookPath     func(file string) (string, error)
	interfaces   func() ([]sshPairInterface, error)
	hostname     func() (string, error)
	defaultRoute func() (string, error)
}

// productionSSHPairProbe is the real machine: PATH and app-bundle CLIs, the
// system interfaces, and the hostname.
func productionSSHPairProbe() sshPairProbe {
	return sshPairProbe{
		command: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, path, args...).Output()
		},
		lookPath:     exec.LookPath,
		interfaces:   systemSSHPairInterfaces,
		hostname:     os.Hostname,
		defaultRoute: systemSSHPairDefaultInterface,
	}
}

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

func validSSHPairInterfaceName(name string) bool {
	return name != "" && len(name) <= 64 && !strings.ContainsAny(name, " \t\r\n\x00/:")
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

// systemSSHPairInterfaces reads the machine's interfaces without any lookups,
// so it stays fast and offline.
func systemSSHPairInterfaces() ([]sshPairInterface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]sshPairInterface, 0, len(list))
	for _, iface := range list {
		entry := sshPairInterface{
			Name:     iface.Name,
			Up:       iface.Flags&net.FlagUp != 0,
			Loopback: iface.Flags&net.FlagLoopback != 0,
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			entry.Addrs = append(entry.Addrs, addr.String())
		}
		out = append(out, entry)
	}
	return out, nil
}

// sshPairParseIPv4 accepts net.Addr.String output and returns the IPv4 address.
func sshPairParseIPv4(raw string) (net.IP, bool) {
	host := raw
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, false
	}
	return v4, true
}

// sshPairPrivateLANIPv4 matches RFC 1918 IPv4, the addresses a phone on the
// same network can reach.
func sshPairPrivateLANIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	switch {
	case v4[0] == 10:
		return true
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return true
	case v4[0] == 192 && v4[1] == 168:
		return true
	}
	return false
}

// sshPairSharedIPv4 matches 100.64.0.0/10, the address space NetBird and
// Tailscale both tunnel through.
func sshPairSharedIPv4(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

// sshPairDNSName keeps a usable DNS name: no trailing dot, at least one dot,
// and safe to put in the pairing hello.
func sshPairDNSName(value string) string {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	if value == "" || !strings.Contains(value, ".") || net.ParseIP(value) != nil || !validSSHPairAddress(value) {
		return ""
	}
	return value
}

// sshPairTool finds a VPN CLI on PATH first, then in its macOS app bundle.
func sshPairTool(probe sshPairProbe, name string, bundles ...string) (string, bool) {
	if probe.lookPath == nil {
		return "", false
	}
	for _, candidate := range append([]string{name}, bundles...) {
		if path, err := probe.lookPath(candidate); err == nil && path != "" {
			return path, true
		}
	}
	return "", false
}

// sshPairProbeCommand runs one probe with the shared timeout.
func sshPairProbeCommand(probe sshPairProbe, path string, args ...string) ([]byte, error) {
	if probe.command == nil {
		return nil, errors.New("ssh_pair_probe_unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), sshPairProbeTimeout)
	defer cancel()
	return probe.command(ctx, path, args...)
}

// netBirdStatus is the part of `netbird status --json` we use.
type netBirdStatus struct {
	FQDN      string `json:"fqdn"`
	NetBirdIP string `json:"netbirdIp"`
}

// parseNetBirdStatus returns the DNS name and IPv4 address NetBird reports.
func parseNetBirdStatus(raw []byte) (string, string) {
	var status netBirdStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return "", ""
	}
	ip := status.NetBirdIP
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	if v4, ok := sshPairParseIPv4(ip); ok {
		ip = v4.String()
	} else {
		ip = ""
	}
	return sshPairDNSName(status.FQDN), ip
}

// tailscaleStatus is the part of `tailscale status --json` we use.
type tailscaleStatus struct {
	Self struct {
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
	} `json:"Self"`
}

// parseTailscaleStatus returns the DNS name and the first IPv4 Tailscale
// reports; the tailnet name comes with a trailing dot.
func parseTailscaleStatus(raw []byte) (string, string) {
	var status tailscaleStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return "", ""
	}
	ip := ""
	for _, entry := range status.Self.TailscaleIPs {
		if v4, ok := sshPairParseIPv4(entry); ok {
			ip = v4.String()
			break
		}
	}
	return sshPairDNSName(status.Self.DNSName), ip
}

// sshPairInterfaceIPv4 returns the first accepted IPv4 on an up, non-loopback
// interface whose name matches.
func sshPairInterfaceIPv4(interfaces []sshPairInterface, match func(name string) bool, accept func(net.IP) bool) string {
	for _, iface := range interfaces {
		if !iface.Up || iface.Loopback || !match(iface.Name) {
			continue
		}
		for _, raw := range iface.Addrs {
			if ip, ok := sshPairParseIPv4(raw); ok && accept(ip) {
				return ip.String()
			}
		}
	}
	return ""
}

// sshPairTunnelInterface matches the macOS utun and the Linux tunnel names.
func sshPairTunnelInterface(names ...string) func(string) bool {
	return func(name string) bool {
		for _, candidate := range names {
			if name == candidate || (candidate == "utun" && strings.HasPrefix(name, "utun")) {
				return true
			}
		}
		return false
	}
}

var (
	sshPairNetBirdInterface   = sshPairTunnelInterface("wt0", "utun")
	sshPairTailscaleInterface = sshPairTunnelInterface("tailscale0", "utun")
)

// sshPairAddressList collects candidates in preference order: no duplicates,
// never more than sshPairAddressLimit.
type sshPairAddressList struct {
	entries []sshPairAddressCandidate
	seen    map[string]bool
}

func (l *sshPairAddressList) add(address, label string) bool {
	address = strings.TrimSpace(address)
	if address == "" || len(l.entries) >= sshPairAddressLimit || !validSSHPairAddress(address) {
		return false
	}
	key := strings.ToLower(address)
	if l.seen[key] {
		return false
	}
	if l.seen == nil {
		l.seen = map[string]bool{}
	}
	l.seen[key] = true
	l.entries = append(l.entries, sshPairAddressCandidate{Address: address, Label: label})
	return true
}

// detectSSHPairAddresses lists how the phone can reach this computer, best
// effort. Order is the prompt order: NetBird, Tailscale, LAN, then the mDNS
// name. A VPN appears once: its DNS name when it has one, otherwise its IP.
func detectSSHPairAddresses(probe sshPairProbe) []sshPairAddressCandidate {
	var interfaces []sshPairInterface
	if probe.interfaces != nil {
		if detected, err := probe.interfaces(); err == nil {
			interfaces = detected
		}
	}
	list := &sshPairAddressList{}
	netbirdPath, netbirdFound := sshPairTool(probe, "netbird", sshPairNetBirdBundle)
	tailscalePath, tailscaleFound := sshPairTool(probe, "tailscale", sshPairTailscaleBundle)
	// utunN is shared by both VPNs on macOS, so a bare utun address is only
	// attributed to a VPN when that is the only VPN installed.
	bothVPNs := netbirdFound && tailscaleFound

	usedNetBird := false
	if netbirdFound {
		if raw, err := sshPairProbeCommand(probe, netbirdPath, "status", "--json"); err == nil {
			dns, ip := parseNetBirdStatus(raw)
			if dns != "" {
				usedNetBird = list.add(dns, sshPairLabelNetBird)
			} else if ip != "" {
				usedNetBird = list.add(ip, sshPairLabelNetBird)
			}
		}
	}
	if netbirdFound && !usedNetBird && !bothVPNs {
		list.add(sshPairInterfaceIPv4(interfaces, sshPairNetBirdInterface, sshPairSharedIPv4), sshPairLabelNetBird)
	}

	usedTailscale := false
	if tailscaleFound {
		if raw, err := sshPairProbeCommand(probe, tailscalePath, "status", "--json"); err == nil {
			dns, ip := parseTailscaleStatus(raw)
			if dns != "" {
				usedTailscale = list.add(dns, sshPairLabelTailscale)
			} else if ip != "" {
				usedTailscale = list.add(ip, sshPairLabelTailscale)
			}
		}
	}
	if tailscaleFound && !usedTailscale && !bothVPNs {
		list.add(sshPairInterfaceIPv4(interfaces, sshPairTailscaleInterface, sshPairSharedIPv4), sshPairLabelTailscale)
	}

	// LAN: the default-route interface first, then the others, at most two
	// entries, and never a container or VM bridge.
	defaultIface := ""
	if probe.defaultRoute != nil {
		if name, err := probe.defaultRoute(); err == nil {
			defaultIface = strings.TrimSpace(name)
		}
	}
	var lanDefault, lanOther []string
	for _, iface := range interfaces {
		if !iface.Up || iface.Loopback || sshPairVirtualInterface(iface.Name) {
			continue
		}
		for _, raw := range iface.Addrs {
			ip, ok := sshPairParseIPv4(raw)
			if !ok || !sshPairPrivateLANIPv4(ip) {
				continue
			}
			if iface.Name == defaultIface {
				lanDefault = append(lanDefault, ip.String())
			} else {
				lanOther = append(lanOther, ip.String())
			}
		}
	}
	lanAdded := 0
	for _, address := range append(lanDefault, lanOther...) {
		if lanAdded >= sshPairLANLimit {
			break
		}
		if list.add(address, sshPairLabelLAN) {
			lanAdded++
		}
	}

	if probe.hostname != nil {
		if hostname, err := probe.hostname(); err == nil {
			hostname = strings.TrimSpace(hostname)
			if hostname != "" && !strings.Contains(hostname, ".") {
				hostname += ".local"
			}
			list.add(hostname, sshPairLabelSameWiFi)
		}
	}
	return list.entries
}

// sshPairDefaultCandidate is the entry the Enter key takes: the first VPN DNS
// name, because it works away from home; otherwise the mDNS name.
func sshPairDefaultCandidate(candidates []sshPairAddressCandidate) int {
	for i, candidate := range candidates {
		if candidate.Label != sshPairLabelNetBird && candidate.Label != sshPairLabelTailscale {
			continue
		}
		if net.ParseIP(candidate.Address) == nil {
			return i
		}
	}
	for i, candidate := range candidates {
		if candidate.Label == sshPairLabelSameWiFi {
			return i
		}
	}
	return 0
}

// sshPairDefaultAddress is what non-interactive runs use: the same default the
// prompt shows, or the old hostname.local when detection found nothing.
func sshPairDefaultAddress(candidates []sshPairAddressCandidate, hostname string) string {
	if len(candidates) != 0 {
		return candidates[sshPairDefaultCandidate(candidates)].Address
	}
	hostname = strings.TrimSpace(hostname)
	if strings.Contains(hostname, ".") {
		return hostname
	}
	return hostname + ".local"
}

// askSSHPairAddress prints the numbered candidates and returns the chosen
// address. Empty input takes the default, a number picks an entry, and a typed
// address is validated and asked again when bad.
func askSSHPairAddress(reader *bufio.Reader, output io.Writer, candidates []sshPairAddressCandidate, fallback string) (string, error) {
	if len(candidates) == 0 {
		return askSSHPairPlainAddress(reader, output, fallback)
	}
	def := sshPairDefaultCandidate(candidates)
	width := 0
	for _, candidate := range candidates {
		if len(candidate.Address) > width {
			width = len(candidate.Address)
		}
	}
	fmt.Fprintln(output, sshPairAddressQuestion)
	for i, candidate := range candidates {
		fmt.Fprintf(output, "  %d) %-*s %s\n", i+1, width, candidate.Address, candidate.Label)
	}
	bad := fmt.Sprintf("Enter a number from 1 to %d or a host name or IP address.", len(candidates))
	for {
		fmt.Fprintf(output, "Choose 1-%d or type an address [%d]: ", len(candidates), def+1)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", errors.New("ssh_pair_cancelled")
		}
		value := strings.TrimRight(line, "\r\n")
		if value == "" {
			return candidates[def].Address, nil
		}
		value = strings.TrimSpace(value)
		if number, parseErr := strconv.Atoi(value); parseErr == nil {
			if number >= 1 && number <= len(candidates) {
				return candidates[number-1].Address, nil
			}
			fmt.Fprintln(output, bad)
			continue
		}
		if validSSHPairAddress(value) {
			return value, nil
		}
		fmt.Fprintln(output, bad)
	}
}

// askSSHPairPlainAddress is the old single-address prompt, kept for machines
// where detection finds no candidate at all.
func askSSHPairPlainAddress(reader *bufio.Reader, output io.Writer, address string) (string, error) {
	for {
		fmt.Fprintf(output, "SSH address your phone can reach [%s]: ", address)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", errors.New("ssh_pair_cancelled")
		}
		if value := strings.TrimRight(line, "\r\n"); value != "" {
			address = strings.TrimSpace(value)
		}
		if validSSHPairAddress(address) {
			return address, nil
		}
		fmt.Fprintln(output, "Enter a host name or IP address.")
	}
}

// sshPairPromptState carries the values the QR prompts start from.
type sshPairPromptState struct {
	address string
	port    int
	notify  bool
	// askAddress is false with --host: the address was typed on the command
	// line, so the address question is skipped and only the rest is asked.
	askAddress bool
	candidates []sshPairAddressCandidate
}

// askSSHPairSettings asks the QR questions, each with its current value as the
// default. A bad address, port or Y/n answer is asked again.
func askSSHPairSettings(reader *bufio.Reader, output io.Writer, state sshPairPromptState) (sshPairPromptState, error) {
	if state.askAddress {
		address, err := askSSHPairAddress(reader, output, state.candidates, state.address)
		if err != nil {
			return state, err
		}
		state.address = address
	}
	for {
		fmt.Fprintf(output, "SSH port [%d]: ", state.port)
		line, err := reader.ReadString('\n')
		if err != nil {
			return state, errors.New("ssh_pair_cancelled")
		}
		value := strings.TrimSpace(line)
		if value == "" {
			break
		}
		entered, parseErr := strconv.Atoi(value)
		if parseErr != nil || entered < 1 || entered > 65535 {
			fmt.Fprintln(output, "Enter a port from 1 to 65535.")
			continue
		}
		state.port = entered
		break
	}
	for {
		hint := "Y/n"
		if !state.notify {
			hint = "y/N"
		}
		fmt.Fprintf(output, "Turn on task notifications? [%s]: ", hint)
		line, err := reader.ReadString('\n')
		if err != nil {
			return state, errors.New("ssh_pair_cancelled")
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return state, nil
		case "y", "yes":
			state.notify = true
			return state, nil
		case "n", "no":
			state.notify = false
			return state, nil
		default:
			fmt.Fprintln(output, "Answer Y or n.")
		}
	}
}
