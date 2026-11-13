//go:build darwin || linux

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// After the prompts the QR needs one short line, not another instruction
// block: the App's scanner screen already says what to do with the code
// (pairing polish).
func TestSSHPairQRPromptIsOneShortLine(t *testing.T) {
	const want = "Scan this code in Shinphony. Expires in 5 minutes."
	if sshPairQRPrompt != want {
		t.Fatalf("QR prompt = %q, want %q", sshPairQRPrompt, want)
	}
	if strings.Contains(sshPairQRPrompt, "\n") {
		t.Fatal("QR prompt must stay on one line")
	}
	for _, stale := range []string{"photograph", "Set up from a computer", "Add server", "scan this code."} {
		if strings.Contains(sshPairQRPrompt, stale) {
			t.Errorf("QR prompt still contains stale wording %q", stale)
		}
	}
}

func TestSSHPairPromptsAcceptDefaultsAndReask(t *testing.T) {
	var output bytes.Buffer
	state, err := askSSHPairSettings(
		bufio.NewReader(strings.NewReader("\n\n\n")), &output, sshPairPromptState{
			address: "example-mac.local", port: 22, notify: true, askAddress: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	if state.address != "example-mac.local" || state.port != 22 || !state.notify {
		t.Fatalf("defaults = %q %d %v", state.address, state.port, state.notify)
	}
	want := "SSH address your phone can reach [example-mac.local]: " +
		"SSH port [22]: " +
		"Turn on task notifications? [Y/n]: "
	if output.String() != want {
		t.Fatalf("prompt output = %q, want %q", output.String(), want)
	}
}

func TestSSHPairPromptsReaskBadValues(t *testing.T) {
	var output bytes.Buffer
	input := "devbox.local\nnot-a-port\n0\n65536\n2222\nmaybe\nno\n"
	state, err := askSSHPairSettings(
		bufio.NewReader(strings.NewReader(input)), &output, sshPairPromptState{
			address: "example-mac.local", port: 22, notify: true, askAddress: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	if state.address != "devbox.local" || state.port != 2222 || state.notify {
		t.Fatalf("answers = %q %d %v", state.address, state.port, state.notify)
	}
	// "not-a-port", "0" and "65536" are all rejected, each with one sentence.
	if got := strings.Count(output.String(), "Enter a port from 1 to 65535.\n"); got != 3 {
		t.Fatalf("port re-ask count = %d, want 3 in %q", got, output.String())
	}
	if !strings.Contains(output.String(), "Answer Y or n.\n") {
		t.Fatalf("missing Y/n re-ask in %q", output.String())
	}
	if !strings.Contains(output.String(), "Turn on task notifications? [Y/n]: ") {
		t.Fatalf("missing notification prompt in %q", output.String())
	}
}

func TestSSHPairAddressPromptReasks(t *testing.T) {
	var output bytes.Buffer
	input := " \n" +
		"bad host\n" +
		"dev/name\n" +
		"dev@name\n" +
		strings.Repeat("a", 254) + "\n" +
		"devbox.local\n" +
		"\n\n"
	state, err := askSSHPairSettings(
		bufio.NewReader(strings.NewReader(input)), &output, sshPairPromptState{
			address: "example-mac.local", port: 22, notify: true, askAddress: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	if state.address != "devbox.local" || state.port != 22 || !state.notify {
		t.Fatalf("answers = %q %d %v", state.address, state.port, state.notify)
	}
	if got := strings.Count(output.String(), "Enter a host name or IP address.\n"); got != 5 {
		t.Fatalf("address re-ask count = %d, want 5 in %q", got, output.String())
	}
}

func TestSSHPairNotificationsPromptDefaultsToNoWhenFlagSaysNo(t *testing.T) {
	var output bytes.Buffer
	state, err := askSSHPairSettings(
		bufio.NewReader(strings.NewReader("\n\n\n")), &output, sshPairPromptState{
			address: "host", port: 22, notify: false, askAddress: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	if state.notify {
		t.Fatal("empty answer did not keep the no default")
	}
	if !strings.Contains(output.String(), "Turn on task notifications? [y/N]: ") {
		t.Fatalf("prompt = %q", output.String())
	}
	for input, want := range map[string]bool{"y": true, "YES": true, "N": false, "no": false} {
		var out bytes.Buffer
		got, err := askSSHPairSettings(
			bufio.NewReader(strings.NewReader("a\n22\n"+input+"\n")), &out, sshPairPromptState{
				address: "host", port: 22, notify: !want, askAddress: true,
			})
		if err != nil || got.notify != want {
			t.Fatalf("answer %q = %v, %v; want %v", input, got.notify, err, want)
		}
	}
}

func TestSSHPairOptions(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want sshPairOptions
	}{
		{"defaults", nil, sshPairOptions{port: 22, localPort: 22, notify: true}},
		{"flags", []string{"--host", "dev.local", "--port", "2222", "--local-port", "2200", "--notify"}, sshPairOptions{address: "dev.local", port: 2222, localPort: 2200, notify: true}},
		{"no-notify", []string{"--no-notify"}, sshPairOptions{port: 22, localPort: 22}},
		{"notify false", []string{"--notify=false"}, sshPairOptions{port: 22, localPort: 22}},
		{"no-notify false", []string{"--no-notify=false"}, sshPairOptions{port: 22, localPort: 22, notify: true}},
		{"invitation", []string{"--invitation-stdin", "--port", "2222"}, sshPairOptions{fromStdin: true, port: 2222, localPort: 22, notify: true}},
	}
	for _, tc := range cases {
		got, err := parseSSHPairOptions(tc.args)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	for _, args := range [][]string{
		{"--notify", "--no-notify"},
		{"--port", "0"},
		{"--port", "65536"},
		{"--port", "not-a-port"},
		{"--local-port", "0"},
		{"extra"},
	} {
		if _, err := parseSSHPairOptions(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestSSHPairNonTerminalInputIsNotInteractive(t *testing.T) {
	if sshPairTerminalInput(strings.NewReader("")) {
		t.Fatal("a strings.Reader is not a terminal")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if sshPairTerminalInput(r) {
		t.Fatal("a pipe is not a terminal")
	}
}

func pairIntentID() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa7}, 16))
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, stateDirectoryName)
}

func privateTestHome(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return base
}

// The App checks for a running service right after the receipt, so the service
// has to be started before the intent file and the receipt (pairing polish).
func TestSSHPairServiceStartsBeforeIntentAndReceipt(t *testing.T) {
	home := privateTestHome(t)
	id := pairIntentID()
	intent := filepath.Join(home, stateDirectoryName, sshPairIntentPrefix+id+".json")
	var output bytes.Buffer
	var steps []string
	install := func(dir, creds string) error {
		if dir != filepath.Join(home, stateDirectoryName) || creds != filepath.Join(home, credentialsDirectoryName) {
			t.Errorf("service dirs = %q %q", dir, creds)
		}
		// The intent must not exist yet: the service is set up first.
		if _, err := os.Stat(intent); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("intent existed before the service started: %v", err)
		}
		steps = append(steps, "service")
		return nil
	}
	receipt := func() error {
		if _, err := os.Stat(intent); err != nil {
			t.Errorf("intent missing when the receipt was sent: %v", err)
		}
		steps = append(steps, "receipt")
		return nil
	}
	if err := finishSSHPairInstall(true, home, id, time.Now(), &output, install, receipt); err != nil {
		t.Fatal(err)
	}
	if strings.Join(steps, ",") != "service,receipt" {
		t.Fatalf("steps = %v, want service then receipt", steps)
	}
	if output.String() != sshPairServiceReadyLine+"\n" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestSSHPairServiceFailureWarnsAndContinues(t *testing.T) {
	home := privateTestHome(t)
	id := pairIntentID()
	var output bytes.Buffer
	receiptSent := false
	err := finishSSHPairInstall(true, home, id, time.Now(), &output,
		func(string, string) error { return errors.New("service_manager_failed: launchctl") },
		func() error { receiptSent = true; return nil })
	if err != nil {
		t.Fatalf("a service failure aborted the pairing: %v", err)
	}
	if !receiptSent {
		t.Fatal("receipt was not sent after a service failure")
	}
	if output.String() != sshPairServiceWarning+"\n" {
		t.Fatalf("output = %q", output.String())
	}
	// The notification intent is still written, so the App can offer the manual
	// action.
	if _, err := os.Stat(filepath.Join(home, stateDirectoryName, sshPairIntentPrefix+id+".json")); err != nil {
		t.Fatalf("intent missing after a service failure: %v", err)
	}
}

func TestSSHPairNoNotifyLeavesServiceAlone(t *testing.T) {
	home := privateTestHome(t)
	var output bytes.Buffer
	receiptSent := false
	err := finishSSHPairInstall(false, home, pairIntentID(), time.Now(), &output,
		func(string, string) error {
			t.Error("service was started although notifications were declined")
			return nil
		},
		func() error { receiptSent = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !receiptSent {
		t.Fatal("receipt was not sent")
	}
	if output.Len() != 0 {
		t.Fatalf("no-notify wrote %q", output.String())
	}
	if _, err := os.Stat(filepath.Join(home, stateDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no-notify created the state directory: %v", err)
	}
}

// The service lines are one line each and never suggest the pairing failed.
func TestSSHPairServiceLines(t *testing.T) {
	if sshPairServiceReadyLine != "Shinphony Hook is running." {
		t.Fatalf("ready line = %q", sshPairServiceReadyLine)
	}
	if sshPairServiceWarning != "Could not start Shinphony Hook; set it up from Shinphony." {
		t.Fatalf("warning line = %q", sshPairServiceWarning)
	}
	for _, line := range []string{sshPairServiceReadyLine, sshPairServiceWarning} {
		if strings.Contains(line, "\n") {
			t.Fatalf("line is not one line: %q", line)
		}
	}
}

// The App calls `ensure-service` without flags, so pairing must use the same
// default directories.
func TestSSHPairServiceDirsMatchTheAppDefaults(t *testing.T) {
	dir, creds := sshPairServiceDirs("/home/dev")
	if dir != "/home/dev/.shinphony-agent" || creds != "/home/dev/.shinphony-notify" {
		t.Fatalf("service dirs = %q %q", dir, creds)
	}
}

func TestSSHPairIntentFailureWarnsAndContinues(t *testing.T) {
	var noOutput bytes.Buffer
	id := pairIntentID()
	now := time.Now()
	noNotifyDir := privateTestDir(t)
	tryRecordSSHPairIntent(false, noNotifyDir, id, now, &noOutput)
	if noOutput.Len() != 0 {
		t.Fatalf("no-notify wrote %q", noOutput.String())
	}
	if _, err := os.Stat(noNotifyDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no-notify created the state directory: %v", err)
	}

	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	notADirectory := filepath.Join(base, "state")
	if err = os.WriteFile(notADirectory, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	tryRecordSSHPairIntent(true, notADirectory, id, now, &output)
	if output.String() != sshPairIntentWarning+"\n" {
		t.Fatalf("warning = %q", output.String())
	}

	var okOutput bytes.Buffer
	tryRecordSSHPairIntent(true, privateTestDir(t), id, now, &okOutput)
	if okOutput.Len() != 0 {
		t.Fatalf("successful intent wrote %q", okOutput.String())
	}
}

func TestSSHPairFinalLineIsShort(t *testing.T) {
	if sshPairDoneLine != "Done. Finish on your phone." {
		t.Fatalf("final line = %q", sshPairDoneLine)
	}
}

func TestSSHPairIntentIsWrittenOnlyWhenRequested(t *testing.T) {
	dir := privateTestDir(t)
	id := pairIntentID()
	now := time.Now()
	if err := recordSSHPairIntent(false, dir, id, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no-notify still created the state directory: %v", err)
	}
	if err := recordSSHPairIntent(true, dir, id, now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pair-intent-"+id+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"notify":true}` {
		t.Fatalf("intent = %q", raw)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Fatalf("intent mode = %o, want 600", mode)
	}
	// Atomic: the temp file is renamed, so nothing else is left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("directory entries = %v", entries)
	}
}

func TestSSHPairIntentPrunesOnlyDayOldFiles(t *testing.T) {
	dir := privateTestDir(t)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	write := func(name string, age time.Duration) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		stamp := now.Add(-age)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	old := "pair-intent-" + pairIntentID() + ".json"
	fresh := "pair-intent-" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xb8}, 16)) + ".json"
	unrelated := "pair-intent-not-json"
	write(old, 25*time.Hour)
	write(fresh, 23*time.Hour)
	write(unrelated, 25*time.Hour)
	id := pairIntentID()
	if err := writeSSHPairIntent(dir, id, now); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		old:                           false,
		fresh:                         true,
		unrelated:                     true,
		"pair-intent-" + id + ".json": true,
	} {
		_, err := os.Stat(filepath.Join(dir, name))
		if got := err == nil; got != want {
			t.Errorf("%s exists = %v, want %v (%v)", name, got, want, err)
		}
	}
}

func TestSSHPairIntentRejectsUnsafeInvitationID(t *testing.T) {
	dir := privateTestDir(t)
	for _, id := range []string{"", "../../escape", "not-base64!", base64.RawURLEncoding.EncodeToString([]byte("short"))} {
		if err := writeSSHPairIntent(dir, id, time.Now()); err == nil {
			t.Errorf("invitation ID %q accepted", id)
		}
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected ID still created the state directory: %v", err)
	}
}
