//go:build darwin || linux

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// sshPairQRPrompt is the one line shown above the pairing QR, after the
// prompts (pairing polish). The App's scanner itself says what to do with it.
const sshPairQRPrompt = "Scan this code in Shinphony. Expires in 5 minutes."

const sshPairIntentPrefix = "pair-intent-"

const sshPairIntentWarning = "Could not save the notification choice; turn notifications on in Shinphony."

const sshPairDoneLine = "Done. Finish on your phone."

// After the key install the pairing starts the user service, so the App finds a
// running Hook when it checks. Neither outcome may fail the pairing: the key is
// already installed, and the service can still be set up from the App.
const (
	sshPairServiceReadyLine = "Shinphony Hook is running."
	sshPairServiceWarning   = "Could not start Shinphony Hook; set it up from Shinphony."
)

type sshPairOptions struct {
	fromStdin bool
	address   string
	port      int
	localPort int
	notify    bool
}

// parseSSHPairOptions keeps the non-interactive contract in one place: flags
// win, and notifications default to on, exactly like the prompt's [Y/n].
func parseSSHPairOptions(args []string) (sshPairOptions, error) {
	opts := sshPairOptions{port: 22, localPort: 22, notify: true}
	flags := flag.NewFlagSet("pair", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Bool("ssh", false, "display a short-lived SSH pairing QR")
	flags.BoolVar(&opts.fromStdin, "invitation-stdin", false, "read an App invitation from stdin")
	flags.StringVar(&opts.address, "host", "", "SSH address reachable from the phone (skips the address prompt)")
	flags.IntVar(&opts.port, "port", 22, "SSH port reachable from the phone")
	flags.IntVar(&opts.localPort, "local-port", 22, "local sshd port for host-key verification")
	notify := flags.Bool("notify", true, "turn on task notifications after pairing")
	noNotify := flags.Bool("no-notify", false, "leave task notifications off after pairing")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || opts.port < 1 || opts.port > 65535 || opts.localPort < 1 || opts.localPort > 65535 {
		return opts, errors.New("ssh_pair_invalid_arguments")
	}
	seen := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	if seen["notify"] && seen["no-notify"] {
		return opts, errors.New("ssh_pair_invalid_arguments")
	}
	if seen["notify"] {
		opts.notify = *notify
	}
	if seen["no-notify"] {
		opts.notify = !*noNotify
	}
	return opts, nil
}

// sshPairTerminalInput distinguishes an interactive terminal from the piped
// stdin that non-interactive callers use. Prompts are skipped when it is false.
func sshPairTerminalInput(input io.Reader) bool {
	file, ok := input.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func validSSHPairAddress(value string) bool {
	return len(value) >= 1 && len(value) <= 253 && !strings.ContainsAny(value, "\r\n\x00 /@")
}

// recordSSHPairIntent writes the App hand-off file only when notifications were
// requested. It is called after the key install and before the receipt, so the
// App can read it as soon as the receipt arrives.
func recordSSHPairIntent(notify bool, stateDir, invitationID string, now time.Time) error {
	if !notify {
		return nil
	}
	return writeSSHPairIntent(stateDir, invitationID, now)
}

// tryRecordSSHPairIntent never fails the pairing: the key is already installed
// and the receipt is about to be sent, so a missing intent only leaves the
// manual notification action in the App.
func tryRecordSSHPairIntent(notify bool, stateDir, invitationID string, now time.Time, output io.Writer) {
	if err := recordSSHPairIntent(notify, stateDir, invitationID, now); err != nil {
		fmt.Fprintln(output, sshPairIntentWarning)
	}
}

// sshPairServiceDirs returns the directories the App's `ensure-service` call
// uses, i.e. the defaults of --state-dir and --credentials-dir.
func sshPairServiceDirs(home string) (string, string) {
	return filepath.Join(home, stateDirectoryName), filepath.Join(home, credentialsDirectoryName)
}

// startSSHPairService runs the service setup the App runs remotely and prints
// one line either way. install is a parameter so tests never reach a real
// launchd or systemd.
func startSSHPairService(home string, output io.Writer, install func(dir, creds string) error) {
	dir, creds := sshPairServiceDirs(home)
	// The service helpers print a JSON status line for the App's remote call;
	// keep it off the user's terminal during pairing.
	stdout := os.Stdout
	if null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		os.Stdout = null
		defer null.Close()
	}
	err := install(dir, creds)
	os.Stdout = stdout
	if err != nil {
		fmt.Fprintln(output, sshPairServiceWarning)
		return
	}
	fmt.Fprintln(output, sshPairServiceReadyLine)
}

// finishSSHPairInstall runs the steps between the key install and the final
// line in the order the App depends on: service, then the intent file, then the
// receipt. The App reads the intent and checks the service right after the
// receipt arrives. Only the receipt error is returned.
func finishSSHPairInstall(notify bool, home, invitationID string, now time.Time, output io.Writer, install func(dir, creds string) error, receipt func() error) error {
	if notify {
		startSSHPairService(home, output, install)
		tryRecordSSHPairIntent(notify, filepath.Join(home, stateDirectoryName), invitationID, now, output)
	}
	return receipt()
}

func sshPairIntentPath(stateDir, invitationID string) (string, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(invitationID)
	if err != nil || len(raw) != 16 {
		return "", errors.New("ssh_pair_intent_invalid")
	}
	return filepath.Join(stateDir, sshPairIntentPrefix+invitationID+".json"), nil
}

func pruneSSHPairIntents(stateDir string, now time.Time) {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return
	}
	cutoff := now.Add(-24 * time.Hour)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, sshPairIntentPrefix) || !strings.HasSuffix(name, ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || !info.ModTime().Before(cutoff) {
			continue
		}
		_ = os.Remove(filepath.Join(stateDir, name))
	}
}

// writeSSHPairIntent creates the private agent directory if needed, prunes
// day-old intents, then writes the new one atomically with mode 600.
func writeSSHPairIntent(stateDir, invitationID string, now time.Time) error {
	path, err := sshPairIntentPath(stateDir, invitationID)
	if err != nil {
		return err
	}
	if err = prepareDir(stateDir); err != nil {
		return errors.New("ssh_pair_intent_directory_unavailable")
	}
	pruneSSHPairIntents(stateDir, now)
	file, err := os.CreateTemp(stateDir, ".pair-intent-")
	if err != nil {
		return errors.New("ssh_pair_intent_write_failed")
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err = file.Chmod(0600); err == nil {
		_, err = file.WriteString(`{"notify":true}`)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("ssh_pair_intent_write_failed")
	}
	if err = os.Rename(temp, path); err != nil {
		return errors.New("ssh_pair_intent_write_failed")
	}
	return nil
}

func sshPairSelected(args []string) bool {
	if len(args) == 0 || args[0] != "pair" {
		return false
	}
	if len(args) > 1 {
		return args[1] == "--ssh" || args[1] == "--invitation-stdin"
	}
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func localSSHPins(port int) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/ssh-keyscan", "-T", "3", "-p", fmt.Sprint(port), "-t", "ed25519,ecdsa,rsa", "127.0.0.1").Output()
	if err != nil || len(output) > 16384 {
		return nil, errors.New("ssh_pair_local_ssh_unavailable")
	}
	pins := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		blob, err := base64.StdEncoding.Strict().DecodeString(fields[2])
		if err != nil || len(blob) > 8192 {
			continue
		}
		hash := sha256.Sum256(blob)
		pin := "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
		if !seen[pin] {
			pins = append(pins, pin)
			seen[pin] = true
		}
	}
	if len(pins) == 0 || len(pins) > 4 {
		return nil, errors.New("ssh_pair_local_ssh_unavailable")
	}
	return pins, nil
}

func sshPairCLI(args []string, input io.Reader, output io.Writer) error {
	if os.Geteuid() == 0 {
		return errors.New("keys_root_not_supported")
	}
	opts, err := parseSSHPairOptions(args)
	if err != nil {
		return err
	}
	var invitation sshPairInvitation
	var tty *os.File
	var reader *bufio.Reader
	if opts.fromStdin {
		raw, err := io.ReadAll(io.LimitReader(input, 2049))
		if err != nil || len(raw) > 2048 {
			return errors.New("invalid_ssh_pair_invitation")
		}
		invitation, err = parseSSHPairInvitation(strings.TrimSpace(string(raw)), time.Now())
		if err != nil || invitation.Mode != "command" {
			return errors.New("invalid_ssh_pair_invitation")
		}
	} else {
		var err error
		tty, err = os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return errors.New("ssh_pair_interactive_terminal_required")
		}
		defer tty.Close()
		reader = bufio.NewReader(tty)
		invitation, err = newSSHPairInvitation("qr")
		if err != nil {
			return err
		}
	}
	hostname, err := os.Hostname()
	if err != nil {
		return errors.New("ssh_pair_hostname_unavailable")
	}
	if len(hostname) > 80 || strings.ContainsAny(hostname, "\r\n\x00") {
		return errors.New("ssh_pair_hostname_invalid")
	}
	// --host skips detection and the address question; otherwise the default is
	// also what a non-interactive run uses.
	addressGiven := opts.address != ""
	var candidates []sshPairAddressCandidate
	if !addressGiven {
		candidates = detectSSHPairAddresses(productionSSHPairProbe())
		opts.address = sshPairDefaultAddress(candidates, hostname)
	}
	if tty != nil && sshPairTerminalInput(input) {
		state, err := askSSHPairSettings(reader, tty, sshPairPromptState{
			address:    opts.address,
			port:       opts.port,
			notify:     opts.notify,
			askAddress: !addressGiven,
			candidates: candidates,
		})
		if err != nil {
			return err
		}
		opts.address, opts.port, opts.notify = state.address, state.port, state.notify
	}
	if !validSSHPairAddress(opts.address) {
		return errors.New("ssh_pair_address_invalid")
	}
	account, err := user.Current()
	if err != nil || len(account.Username) > 64 || strings.ContainsAny(account.Username, "\r\n\x00") {
		return errors.New("ssh_pair_user_unavailable")
	}
	pins, err := localSSHPins(opts.localPort)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		return err
	}
	binaryHash := sha256.Sum256(binary)
	transport := productionSSHPairTransport()
	reply, err := transport.create(invitation)
	if err != nil {
		return err
	}
	if reply.ID != invitation.ID || reply.Expires <= time.Now().UnixMilli() || reply.Expires > time.Now().Add(5*time.Minute+10*time.Second).UnixMilli() {
		return errors.New("ssh_pair_response_invalid")
	}
	invitation.Expires = reply.Expires
	hello, err := invitation.seal("hello", hostname, opts.address, opts.port, account.Username, pins, hex.EncodeToString(binaryHash[:]), invitation.Mode, invitation.Expires)
	if err != nil {
		return err
	}
	if _, err = transport.exchange(invitation, "hello", &hello); err != nil {
		return err
	}
	duration := time.Until(time.UnixMilli(invitation.Expires))
	if duration > 5*time.Minute {
		duration = 5 * time.Minute
	}
	deadline := time.Now().Add(duration)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if tty != nil {
		invitation.HelloHash = sshPairHash(hello.Payload)
		raw, _ := json.Marshal(invitation)
		uri := "shinphony://ssh-pair#" + base64.RawURLEncoding.EncodeToString(raw)
		qr, err := qrcode.New(uri, qrcode.Medium)
		if err != nil {
			return err
		}
		fmt.Fprintf(tty, "\n%s\n%s\nPrivate pairing link (paste only into Shinphony):\n%s\n", sshPairQRPrompt, qr.ToSmallString(false), uri)
		go func() { <-ctx.Done(); tty.Close() }()
	} else {
		fmt.Fprintln(output, "Waiting for your phone to review this computer. Keep this command running.")
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if time.Until(deadline) <= 0 {
			return errors.New("ssh_pair_expired")
		}
		mailbox, err := transport.exchange(invitation, "", nil)
		if err != nil {
			return err
		}
		if mailbox.ID != invitation.ID || mailbox.Expires != invitation.Expires {
			return errors.New("ssh_pair_response_invalid")
		}
		if mailbox.Key != nil {
			request, err := invitation.verifyKey(*mailbox.Key, hello, account.Username)
			if err != nil {
				return err
			}
			fingerprint, _ := validateP256PublicKey(request.PublicKey)
			if tty != nil {
				fmt.Fprintf(tty, "Device key: %s\nEnter the six-digit code shown on your phone: ", fingerprint)
				code, err := reader.ReadString('\n')
				if err != nil || strings.TrimSpace(code) != invitation.sas(hello, *mailbox.Key) {
					return errors.New("ssh_pair_confirmation_failed")
				}
			}
			if time.Until(deadline) <= 0 {
				return errors.New("ssh_pair_expired")
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return errors.New("keys_home_unavailable")
			}
			if _, err = manageSSHKey(home, "install", request); err != nil {
				return err
			}
			receipt, err := invitation.seal("receipt", request.ID, sshPairHash(mailbox.Key.Payload), "installed")
			if err != nil {
				return err
			}
			err = finishSSHPairInstall(opts.notify, home, invitation.ID, time.Now(), output, ensureService, func() error {
				_, e := transport.exchange(invitation, "receipt", &receipt)
				return e
			})
			if err != nil {
				return errors.New("ssh_pair_key_installed_receipt_pending: use keys list to inspect access")
			}
			fmt.Fprintln(output, sshPairDoneLine)
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("ssh_pair_expired")
		case <-ticker.C:
		}
	}
}
