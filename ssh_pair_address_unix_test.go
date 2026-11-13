//go:build darwin || linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Fixtures are redacted: only reserved example names and documentation
// addresses appear in them (plan section A).
const netBirdStatusFixture = `{
  "fqdn": "devhost.netbird.example",
  "netbirdIp": "100.100.10.20",
  "management": {"connected": true},
  "peers": {"total": 2}
}`

const tailscaleStatusFixture = `{
  "Version": "1.78.0",
  "Self": {
    "DNSName": "devhost.tail1234.ts.example.",
    "TailscaleIPs": ["100.64.0.11", "fd7a:115c:a1e0::1"]
  }
}`

func TestSSHPairParseNetBirdStatus(t *testing.T) {
	dns, ip := parseNetBirdStatus([]byte(netBirdStatusFixture))
	if dns != "devhost.netbird.example" || ip != "100.100.10.20" {
		t.Fatalf("netbird = %q %q", dns, ip)
	}
	// A CIDR suffix and a trailing dot are tolerated, garbage is ignored.
	if dns, ip := parseNetBirdStatus([]byte(`{"fqdn":"devhost.netbird.example.","netbirdIp":"100.100.10.20/16"}`)); dns != "devhost.netbird.example" || ip != "100.100.10.20" {
		t.Fatalf("netbird with suffix = %q %q", dns, ip)
	}
	if dns, ip := parseNetBirdStatus([]byte("not json")); dns != "" || ip != "" {
		t.Fatalf("garbage accepted: %q %q", dns, ip)
	}
	if dns, ip := parseNetBirdStatus([]byte(`{"fqdn":"localhost","netbirdIp":"not-an-ip"}`)); dns != "" || ip != "" {
		t.Fatalf("unusable values accepted: %q %q", dns, ip)
	}
}

func TestSSHPairParseTailscaleStatus(t *testing.T) {
	dns, ip := parseTailscaleStatus([]byte(tailscaleStatusFixture))
	if dns != "devhost.tail1234.ts.example" || ip != "100.64.0.11" {
		t.Fatalf("tailscale = %q %q", dns, ip)
	}
	// The plan writes TailscaleIPs[0]; real output lists the IPv4 first. An
	// IPv6-first list must still yield a usable IPv4 address.
	if _, ip := parseTailscaleStatus([]byte(`{"Self":{"DNSName":"dev.ts.example.","TailscaleIPs":["fd7a:115c:a1e0::1","100.64.0.12"]}}`)); ip != "100.64.0.12" {
		t.Fatalf("ipv6-first list = %q", ip)
	}
	if dns, ip := parseTailscaleStatus([]byte(`{"Self":{"DNSName":"","TailscaleIPs":[]}}`)); dns != "" || ip != "" {
		t.Fatalf("empty self = %q %q", dns, ip)
	}
}

// pairProbeFixture is a fake environment: tools maps a requested name or path
// to the path LookPath returns, and outputs holds the command output per path.
type pairProbeFixture struct {
	tools        map[string]string
	outputs      map[string]string
	fail         map[string]bool
	interfaces   []sshPairInterface
	hostname     string
	defaultRoute string
	calls        []string
}

func (f *pairProbeFixture) probe() sshPairProbe {
	return sshPairProbe{
		lookPath: func(file string) (string, error) {
			if path, ok := f.tools[file]; ok && path != "" {
				return path, nil
			}
			return "", errors.New("exec: not found")
		},
		command: func(ctx context.Context, path string, args ...string) ([]byte, error) {
			f.calls = append(f.calls, path+" "+strings.Join(args, " "))
			if f.fail[path] {
				return nil, errors.New("exit status 1")
			}
			output, ok := f.outputs[path]
			if !ok {
				return nil, errors.New("no output")
			}
			return []byte(output), nil
		},
		interfaces: func() ([]sshPairInterface, error) { return f.interfaces, nil },
		hostname:   func() (string, error) { return f.hostname, nil },
		defaultRoute: func() (string, error) {
			if f.defaultRoute == "" {
				return "", errors.New("no default route")
			}
			return f.defaultRoute, nil
		},
	}
}

func pairAddresses(candidates []sshPairAddressCandidate) []string {
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.Address+" ("+candidate.Label+")")
	}
	return out
}

func TestSSHPairAddressDetectionOrderAndLabels(t *testing.T) {
	fixture := &pairProbeFixture{
		tools: map[string]string{
			"netbird":   "/opt/homebrew/bin/netbird",
			"tailscale": "/usr/local/bin/tailscale",
		},
		outputs: map[string]string{
			"/opt/homebrew/bin/netbird": netBirdStatusFixture,
			"/usr/local/bin/tailscale":  tailscaleStatusFixture,
		},
		interfaces: []sshPairInterface{
			{Name: "lo0", Up: true, Loopback: true, Addrs: []string{"127.0.0.1/8", "::1/128"}},
			{Name: "en0", Up: true, Addrs: []string{"fe80::1%en0/64", "192.168.50.10/24"}},
			{Name: "wt0", Up: true, Addrs: []string{"100.100.10.20/16"}},
			{Name: "tailscale0", Up: true, Addrs: []string{"100.64.0.11/32"}},
			{Name: "en5", Up: false, Addrs: []string{"192.168.9.9/24"}},
		},
		hostname: "devhost",
	}
	got := pairAddresses(detectSSHPairAddresses(fixture.probe()))
	want := []string{
		"devhost.netbird.example (NetBird)",
		"devhost.tail1234.ts.example (Tailscale)",
		"192.168.50.10 (LAN)",
		"devhost.local (Same Wi-Fi)",
	}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}

// The CLIs are asked with `status --json`, and only once each.
func TestSSHPairAddressDetectionAsksTheCLIs(t *testing.T) {
	fixture := &pairProbeFixture{
		tools:      map[string]string{"netbird": "/usr/bin/netbird", "tailscale": "/usr/bin/tailscale"},
		outputs:    map[string]string{"/usr/bin/netbird": netBirdStatusFixture, "/usr/bin/tailscale": tailscaleStatusFixture},
		interfaces: nil,
		hostname:   "devbox",
	}
	detectSSHPairAddresses(fixture.probe())
	want := []string{"/usr/bin/netbird status --json", "/usr/bin/tailscale status --json"}
	if strings.Join(fixture.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls = %v, want %v", fixture.calls, want)
	}
}

func TestSSHPairAddressDetectionDeduplicates(t *testing.T) {
	// The NetBird IP is also on a LAN-named interface, and two interfaces share
	// the same LAN address: only the first label survives. The VPN is listed
	// once (its DNS name), so its IP never reaches the list.
	fixture := &pairProbeFixture{
		tools:   map[string]string{"netbird": "/usr/bin/netbird"},
		outputs: map[string]string{"/usr/bin/netbird": netBirdStatusFixture},
		interfaces: []sshPairInterface{
			{Name: "en0", Up: true, Addrs: []string{"100.100.10.20/16", "10.0.0.5/8"}},
			{Name: "en1", Up: true, Addrs: []string{"10.0.0.5/24"}},
		},
		hostname: "devhost",
	}
	got := pairAddresses(detectSSHPairAddresses(fixture.probe()))
	want := []string{
		"devhost.netbird.example (NetBird)",
		"10.0.0.5 (LAN)",
		"devhost.local (Same Wi-Fi)",
	}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}

// Detection can no longer fill six entries (two VPNs, two LAN, one mDNS), but
// the list still enforces the cap.
func TestSSHPairAddressListIsCappedAtSix(t *testing.T) {
	list := &sshPairAddressList{}
	for i := 1; i <= 8; i++ {
		list.add("192.0.2."+strconv.Itoa(i), sshPairLabelLAN)
	}
	if len(list.entries) != sshPairAddressLimit {
		t.Fatalf("entries = %d, want %d", len(list.entries), sshPairAddressLimit)
	}
	if !list.seen["192.0.2.6"] || list.seen["192.0.2.7"] {
		t.Fatalf("the wrong entries survived: %v", list.seen)
	}
}

// How the phone reaches the computer: no container or VM interfaces, at most
// two LAN entries, and the default-route interface first.
func TestSSHPairAddressDetectionSkipsVirtualInterfaces(t *testing.T) {
	fixture := &pairProbeFixture{
		interfaces: []sshPairInterface{
			{Name: "lo0", Up: true, Loopback: true, Addrs: []string{"127.0.0.1/8"}},
			{Name: "docker0", Up: true, Addrs: []string{"172.17.0.1/16"}},
			{Name: "br-1a2b3c", Up: true, Addrs: []string{"172.18.0.1/16"}},
			{Name: "veth0f1e", Up: true, Addrs: []string{"10.0.0.5/24"}},
			{Name: "bridge100", Up: true, Addrs: []string{"192.168.2.1/24"}},
			{Name: "vmnet1", Up: true, Addrs: []string{"192.168.3.1/24"}},
			{Name: "vboxnet0", Up: true, Addrs: []string{"192.168.4.1/24"}},
			{Name: "virbr0", Up: true, Addrs: []string{"192.168.5.1/24"}},
			{Name: "cni0", Up: true, Addrs: []string{"10.0.1.1/24"}},
			{Name: "flannel.1", Up: true, Addrs: []string{"10.0.2.1/24"}},
			{Name: "cali123", Up: true, Addrs: []string{"10.0.3.1/24"}},
			{Name: "en0", Up: true, Addrs: []string{"192.168.50.10/24"}},
		},
		hostname: "devhost",
	}
	got := pairAddresses(detectSSHPairAddresses(fixture.probe()))
	want := []string{"192.168.50.10 (LAN)", "devhost.local (Same Wi-Fi)"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}

func TestSSHPairAddressDetectionPutsTheDefaultRouteFirst(t *testing.T) {
	interfaces := []sshPairInterface{
		{Name: "en0", Up: true, Addrs: []string{"10.2.0.5/24"}},
		{Name: "en1", Up: true, Addrs: []string{"192.168.50.10/24"}},
		{Name: "en2", Up: true, Addrs: []string{"172.16.0.5/24"}},
	}
	// The Wi-Fi network carries the default route, so it is listed first even
	// though the interface order says otherwise; the third LAN is dropped.
	fixture := &pairProbeFixture{interfaces: interfaces, hostname: "devhost", defaultRoute: "en1"}
	got := pairAddresses(detectSSHPairAddresses(fixture.probe()))
	want := []string{"192.168.50.10 (LAN)", "10.2.0.5 (LAN)", "devhost.local (Same Wi-Fi)"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}

	// Without a routing answer the interface order stands, still capped at two.
	unknown := &pairProbeFixture{interfaces: interfaces, hostname: "devhost"}
	got = pairAddresses(detectSSHPairAddresses(unknown.probe()))
	want = []string{"10.2.0.5 (LAN)", "192.168.50.10 (LAN)", "devhost.local (Same Wi-Fi)"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}

// A VPN without a DNS name is listed by IP; with a name the IP is dropped.
func TestSSHPairAddressDetectionListsOneEntryPerVPN(t *testing.T) {
	ipOnly := &pairProbeFixture{
		tools:    map[string]string{"netbird": "/usr/bin/netbird"},
		outputs:  map[string]string{"/usr/bin/netbird": `{"fqdn":"","netbirdIp":"100.100.10.20"}`},
		hostname: "devhost",
	}
	got := pairAddresses(detectSSHPairAddresses(ipOnly.probe()))
	want := []string{"100.100.10.20 (NetBird)", "devhost.local (Same Wi-Fi)"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("netbird without a name = %v, want %v", got, want)
	}

	tailscaleNamed := &pairProbeFixture{
		tools:    map[string]string{"tailscale": "/usr/bin/tailscale"},
		outputs:  map[string]string{"/usr/bin/tailscale": `{"Self":{"DNSName":"devhost.ts.example.","TailscaleIPs":["100.64.0.11"]}}`},
		hostname: "devhost",
	}
	got = pairAddresses(detectSSHPairAddresses(tailscaleNamed.probe()))
	want = []string{"devhost.ts.example (Tailscale)", "devhost.local (Same Wi-Fi)"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("tailscale with a name = %v, want %v", got, want)
	}

	tailscaleIPOnly := &pairProbeFixture{
		tools:    map[string]string{"tailscale": "/usr/bin/tailscale"},
		outputs:  map[string]string{"/usr/bin/tailscale": `{"Self":{"DNSName":"","TailscaleIPs":["100.64.0.11"]}}`},
		hostname: "devhost",
	}
	got = pairAddresses(detectSSHPairAddresses(tailscaleIPOnly.probe()))
	want = []string{"100.64.0.11 (Tailscale)", "devhost.local (Same Wi-Fi)"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("tailscale without a name = %v, want %v", got, want)
	}
}

func TestSSHPairDefaultRouteParsers(t *testing.T) {
	darwin := `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
`
	if name, err := parseSSHPairDarwinDefaultRoute([]byte(darwin)); err != nil || name != "en0" {
		t.Fatalf("darwin default route = %q, %v", name, err)
	}
	if _, err := parseSSHPairDarwinDefaultRoute([]byte("no route")); err == nil {
		t.Fatal("garbage darwin route accepted")
	}

	linux := `default via 192.168.1.1 dev enp0s3 proto dhcp src 192.168.50.10 metric 100
default via 10.0.0.1 dev wlan0 metric 600
`
	if name, err := parseSSHPairLinuxDefaultRoute([]byte(linux)); err != nil || name != "enp0s3" {
		t.Fatalf("linux default route = %q, %v", name, err)
	}
	if _, err := parseSSHPairLinuxDefaultRoute([]byte("default via 192.168.1.1")); err == nil {
		t.Fatal("linux route without dev accepted")
	}
}

func TestSSHPairVirtualInterfaceFilter(t *testing.T) {
	for name, want := range map[string]bool{
		"docker0": true, "br-1a2b3c": true, "veth0f1e": true, "virbr0": true,
		"cni0": true, "flannel.1": true, "cali123": true, "vmnet1": true,
		"vboxnet0": true, "bridge100": true, "bridge0": true,
		"en0": false, "en1": false, "utun3": false, "wt0": false, "tailscale0": false,
	} {
		if got := sshPairVirtualInterface(name); got != want {
			t.Errorf("sshPairVirtualInterface(%q) = %v, want %v", name, got, want)
		}
	}
}

// Without a working CLI the tunnel interface is the fallback. The label is the
// only VPN installed, so a bare utun address is unambiguous.
func TestSSHPairAddressDetectionFallsBackToTheTunnelInterface(t *testing.T) {
	fixture := &pairProbeFixture{
		tools:      map[string]string{"netbird": "/usr/bin/netbird"},
		fail:       map[string]bool{"/usr/bin/netbird": true},
		interfaces: []sshPairInterface{{Name: "utun3", Up: true, Addrs: []string{"100.100.1.5/32"}}},
		hostname:   "devhost",
	}
	got := pairAddresses(detectSSHPairAddresses(fixture.probe()))
	want := []string{"100.100.1.5 (NetBird)", "devhost.local (Same Wi-Fi)"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}

	tailscale := &pairProbeFixture{
		tools:      map[string]string{"tailscale": "/usr/bin/tailscale"},
		fail:       map[string]bool{"/usr/bin/tailscale": true},
		interfaces: []sshPairInterface{{Name: "tailscale0", Up: true, Addrs: []string{"100.64.0.11/32"}}},
		hostname:   "devhost",
	}
	got = pairAddresses(detectSSHPairAddresses(tailscale.probe()))
	want = []string{"100.64.0.11 (Tailscale)", "devhost.local (Same Wi-Fi)"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}

// With both VPNs installed, a bare utun address cannot be attributed, so it is
// skipped and the LAN and mDNS entries still make a usable list.
func TestSSHPairAddressDetectionSkipsAmbiguousUtun(t *testing.T) {
	fixture := &pairProbeFixture{
		tools: map[string]string{"netbird": "/usr/bin/netbird", "tailscale": "/usr/local/bin/tailscale"},
		fail:  map[string]bool{"/usr/bin/netbird": true, "/usr/local/bin/tailscale": true},
		interfaces: []sshPairInterface{
			{Name: "utun4", Up: true, Addrs: []string{"100.64.0.99/32"}},
			{Name: "en0", Up: true, Addrs: []string{"192.168.50.10/24"}},
		},
		hostname: "devhost",
	}
	got := pairAddresses(detectSSHPairAddresses(fixture.probe()))
	want := []string{"192.168.50.10 (LAN)", "devhost.local (Same Wi-Fi)"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}

// The macOS app bundles are probed after PATH, so a CLI installed both ways is
// not queried twice.
func TestSSHPairAddressDetectionFindsAppBundles(t *testing.T) {
	fixture := &pairProbeFixture{
		tools:    map[string]string{sshPairNetBirdBundle: sshPairNetBirdBundle},
		outputs:  map[string]string{sshPairNetBirdBundle: netBirdStatusFixture},
		hostname: "devhost",
	}
	got := pairAddresses(detectSSHPairAddresses(fixture.probe()))
	want := []string{"devhost.netbird.example (NetBird)", "devhost.local (Same Wi-Fi)"}
	if strings.Join(got, ", ") != strings.Join(want, ", ") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	if len(fixture.calls) != 1 || fixture.calls[0] != sshPairNetBirdBundle+" status --json" {
		t.Fatalf("calls = %v", fixture.calls)
	}

	// PATH wins over the bundle when both exist.
	both := &pairProbeFixture{
		tools: map[string]string{
			"netbird":            "/opt/homebrew/bin/netbird",
			sshPairNetBirdBundle: sshPairNetBirdBundle,
		},
		outputs: map[string]string{
			"/opt/homebrew/bin/netbird": netBirdStatusFixture,
			sshPairNetBirdBundle:        netBirdStatusFixture,
		},
		hostname: "devhost",
	}
	detectSSHPairAddresses(both.probe())
	if len(both.calls) != 1 || both.calls[0] != "/opt/homebrew/bin/netbird status --json" {
		t.Fatalf("bundle was used although PATH has the CLI: %v", both.calls)
	}
}

// Detection never fails the pairing: a broken environment just yields what it
// can.
func TestSSHPairAddressDetectionIsBestEffort(t *testing.T) {
	probe := sshPairProbe{
		lookPath:     func(string) (string, error) { return "", errors.New("not found") },
		command:      func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("nope") },
		interfaces:   func() ([]sshPairInterface, error) { return nil, errors.New("no interfaces") },
		hostname:     func() (string, error) { return "", errors.New("no hostname") },
		defaultRoute: func() (string, error) { return "", errors.New("no default route") },
	}
	if got := detectSSHPairAddresses(probe); len(got) != 0 {
		t.Fatalf("candidates = %v, want none", pairAddresses(got))
	}
	if got := detectSSHPairAddresses(sshPairProbe{}); len(got) != 0 {
		t.Fatalf("empty probe = %v, want none", pairAddresses(got))
	}
}

// Each probe runs under a two-second deadline, so a hung VPN CLI cannot block
// the pairing.
func TestSSHPairProbeCommandHasATwoSecondTimeout(t *testing.T) {
	var seen time.Duration
	probe := sshPairProbe{command: func(ctx context.Context, path string, args ...string) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("probe command has no deadline")
			return nil, ctx.Err()
		}
		seen = time.Until(deadline)
		return nil, errors.New("probe failed")
	}}
	if _, err := sshPairProbeCommand(probe, "netbird", "status", "--json"); err == nil {
		t.Fatal("expected the probe error")
	}
	if seen <= 0 || seen > sshPairProbeTimeout {
		t.Fatalf("deadline = %v, want at most %v", seen, sshPairProbeTimeout)
	}
}

func TestSSHPairDefaultAddressPrefersVPNDNS(t *testing.T) {
	candidates := []sshPairAddressCandidate{
		{Address: "100.100.10.20", Label: sshPairLabelNetBird},
		{Address: "devhost.netbird.example", Label: sshPairLabelNetBird},
		{Address: "192.168.50.10", Label: sshPairLabelLAN},
		{Address: "devhost.local", Label: sshPairLabelSameWiFi},
	}
	if got := sshPairDefaultAddress(candidates, "devhost"); got != "devhost.netbird.example" {
		t.Fatalf("default = %q, want the NetBird DNS name", got)
	}
	// No VPN: the mDNS name, even when it is not first.
	lanOnly := []sshPairAddressCandidate{
		{Address: "192.168.50.10", Label: sshPairLabelLAN},
		{Address: "devhost.local", Label: sshPairLabelSameWiFi},
		{Address: "10.0.0.5", Label: sshPairLabelLAN},
	}
	if got := sshPairDefaultAddress(lanOnly, "devhost"); got != "devhost.local" {
		t.Fatalf("default = %q, want devhost.local", got)
	}
	// Nothing detected: the old hostname.local default.
	if got := sshPairDefaultAddress(nil, "devhost"); got != "devhost.local" {
		t.Fatalf("default = %q, want devhost.local", got)
	}
	if got := sshPairDefaultAddress(nil, "devhost.example"); got != "devhost.example" {
		t.Fatalf("default = %q, want the dotted hostname", got)
	}
	if got := sshPairDefaultAddress([]sshPairAddressCandidate{{Address: "192.168.50.10", Label: sshPairLabelLAN}}, "devhost"); got != "192.168.50.10" {
		t.Fatalf("default = %q, want the only LAN address", got)
	}
}

const pairPromptExample = "How will your phone reach this computer?\n" +
	"  1) devhost.netbird.example     NetBird\n" +
	"  2) devhost.tail1234.ts.example Tailscale\n" +
	"  3) 192.168.50.10               LAN\n" +
	"  4) devhost.local               Same Wi-Fi\n"

func pairPromptCandidates() []sshPairAddressCandidate {
	return []sshPairAddressCandidate{
		{Address: "devhost.netbird.example", Label: sshPairLabelNetBird},
		{Address: "devhost.tail1234.ts.example", Label: sshPairLabelTailscale},
		{Address: "192.168.50.10", Label: sshPairLabelLAN},
		{Address: "devhost.local", Label: sshPairLabelSameWiFi},
	}
}

// The prompt lists the candidates with their source, and Enter takes the first
// VPN DNS name.
func TestSSHPairAddressPromptListsCandidates(t *testing.T) {
	var output bytes.Buffer
	address, err := askSSHPairAddress(bufio.NewReader(strings.NewReader("\n")), &output, pairPromptCandidates(), "devhost.local")
	if err != nil {
		t.Fatal(err)
	}
	if address != "devhost.netbird.example" {
		t.Fatalf("default address = %q", address)
	}
	want := pairPromptExample + "Choose 1-4 or type an address [1]: "
	if output.String() != want {
		t.Fatalf("prompt = %q, want %q", output.String(), want)
	}
}

func TestSSHPairAddressPromptSelectsByNumber(t *testing.T) {
	for input, want := range map[string]string{
		"1\n":   "devhost.netbird.example",
		"3\n":   "192.168.50.10",
		"4\n":   "devhost.local",
		" 2 \n": "devhost.tail1234.ts.example",
	} {
		var output bytes.Buffer
		got, err := askSSHPairAddress(bufio.NewReader(strings.NewReader(input)), &output, pairPromptCandidates(), "devhost.local")
		if err != nil || got != want {
			t.Fatalf("input %q = %q, %v; want %q", input, got, err, want)
		}
	}
}

func TestSSHPairAddressPromptAcceptsATypedAddress(t *testing.T) {
	var output bytes.Buffer
	address, err := askSSHPairAddress(
		bufio.NewReader(strings.NewReader("devbox.example\n")), &output, pairPromptCandidates(), "devhost.local")
	if err != nil || address != "devbox.example" {
		t.Fatalf("typed address = %q, %v", address, err)
	}
}

func TestSSHPairAddressPromptReasksBadEntries(t *testing.T) {
	var output bytes.Buffer
	input := "bad host\n" +
		"9\n" +
		"0\n" +
		"dev/name\n" +
		strings.Repeat("a", 254) + "\n" +
		"devbox.example\n"
	address, err := askSSHPairAddress(
		bufio.NewReader(strings.NewReader(input)), &output, pairPromptCandidates(), "devhost.local")
	if err != nil || address != "devbox.example" {
		t.Fatalf("address = %q, %v", address, err)
	}
	const bad = "Enter a number from 1 to 4 or a host name or IP address.\n"
	if got := strings.Count(output.String(), bad); got != 5 {
		t.Fatalf("re-ask count = %d, want 5 in %q", got, output.String())
	}
	if !strings.Contains(output.String(), "Choose 1-4 or type an address [1]: ") {
		t.Fatalf("missing prompt in %q", output.String())
	}
}

// With only LAN and mDNS the default is the mDNS name, because it works on any
// Wi-Fi.
func TestSSHPairAddressPromptDefaultsToTheMDNSName(t *testing.T) {
	var output bytes.Buffer
	candidates := []sshPairAddressCandidate{
		{Address: "192.168.50.10", Label: sshPairLabelLAN},
		{Address: "devhost.local", Label: sshPairLabelSameWiFi},
	}
	address, err := askSSHPairAddress(bufio.NewReader(strings.NewReader("\n")), &output, candidates, "devhost.local")
	if err != nil || address != "devhost.local" {
		t.Fatalf("address = %q, %v", address, err)
	}
	if !strings.Contains(output.String(), "Choose 1-2 or type an address [2]: ") {
		t.Fatalf("prompt = %q", output.String())
	}
}

// No candidates at all keeps the old single-address prompt.
func TestSSHPairAddressPromptWithoutCandidates(t *testing.T) {
	var output bytes.Buffer
	address, err := askSSHPairAddress(bufio.NewReader(strings.NewReader("\n")), &output, nil, "devhost.local")
	if err != nil || address != "devhost.local" {
		t.Fatalf("address = %q, %v", address, err)
	}
	if output.String() != "SSH address your phone can reach [devhost.local]: " {
		t.Fatalf("prompt = %q", output.String())
	}
}

// --host skips the address question but keeps the port and notification ones.
func TestSSHPairSettingsWithHostSkipsTheAddressQuestion(t *testing.T) {
	var output bytes.Buffer
	state, err := askSSHPairSettings(bufio.NewReader(strings.NewReader("\n\n")), &output, sshPairPromptState{
		address: "devbox.example", port: 22, notify: true, candidates: pairPromptCandidates(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.address != "devbox.example" || state.port != 22 || !state.notify {
		t.Fatalf("state = %+v", state)
	}
	want := "SSH port [22]: Turn on task notifications? [Y/n]: "
	if output.String() != want {
		t.Fatalf("prompt = %q, want %q", output.String(), want)
	}
}

// The address question comes first, then the port and notification prompts
// (pairing polish order).
func TestSSHPairSettingsAsksAddressThenPortThenNotifications(t *testing.T) {
	var output bytes.Buffer
	state, err := askSSHPairSettings(bufio.NewReader(strings.NewReader("2\n2222\nn\n")), &output, sshPairPromptState{
		address: "devhost.local", port: 22, notify: true, askAddress: true, candidates: pairPromptCandidates(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.address != "devhost.tail1234.ts.example" || state.port != 2222 || state.notify {
		t.Fatalf("state = %+v", state)
	}
	if !strings.HasPrefix(output.String(), pairPromptExample) {
		t.Fatalf("address prompt is not first: %q", output.String())
	}
}
