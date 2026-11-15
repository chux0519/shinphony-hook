//go:build windows

package main

// The Windows side of `pair`: the console (CONIN$/CONOUT$) for the prompts and
// the QR, the sshd host public keys on disk (with the OpenSSH client's
// ssh-keyscan as the fallback when a filtered administrator token may not read
// ProgramData\ssh), and no root rule (Windows elevates per action, and only the
// administrator key file needs it). The flow itself is in ssh_pair_cli.go.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// sshPairHostKeyFiles are the public host keys sshd generates in
// C:\ProgramData\ssh; their fingerprints are what the App pins.
var sshPairHostKeyFiles = []string{"ssh_host_ed25519_key.pub", "ssh_host_ecdsa_key.pub", "ssh_host_rsa_key.pub"}

func sshPairPrivilegeCheck() error {
	// An administrator's key goes to administrators_authorized_keys, which the
	// key store refuses to touch without elevation (ssh_pair_needs_admin).
	return nil
}

// openSSHPairConsole opens the console handles directly: stdin and stdout may be
// redirected by the one-line installer, and CONIN$ still reaches the user.
// CONOUT$ is opened for read and write because GetConsoleMode, which tells us
// whether the handle is a console, needs GENERIC_READ.
func openSSHPairConsole() (*sshPairConsole, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		in.Close()
		return nil, err
	}
	closeBoth := func() {
		out.Close()
		in.Close()
	}
	return &sshPairConsole{
		input:  bufio.NewReader(in),
		output: newSSHPairWriter(out),
		close:  closeBoth,
	}, nil
}

// sshPairWriter writes the prompts and the QR code so they render whatever code
// page the console uses. On a console it hands the text to WriteConsoleW, which
// takes UTF-16 and bypasses the code page (a code page 936 console showed the
// QR's half-block characters as mojibake when the bytes went through WriteFile).
// On anything that is not a console - a pipe, or an SSH pty that is not a
// console - it writes UTF-8 bytes, which is what such a stream expects.
type sshPairWriter struct {
	// console is the WriteConsoleW path; nil when the handle is not a console.
	console  func(text string) error
	fallback io.Writer
}

func (w sshPairWriter) Write(p []byte) (int, error) {
	if w.console != nil {
		if err := w.console(string(p)); err == nil {
			return len(p), nil
		}
		// A console that rejects the call (for example a handle that is no longer
		// a console) still gets the bytes, as a pipe would.
	}
	if w.fallback == nil {
		return len(p), nil
	}
	return w.fallback.Write(p)
}

// newSSHPairWriter picks the console path for a console handle and UTF-8 bytes
// otherwise.
func newSSHPairWriter(file *os.File) io.Writer {
	var mode uint32
	if windows.GetConsoleMode(windows.Handle(file.Fd()), &mode) != nil {
		return sshPairWriter{fallback: file}
	}
	handle := windows.Handle(file.Fd())
	write := func(text string) error {
		if err := writeConsoleW(handle, text); err != nil {
			return err
		}
		return nil
	}
	return sshPairWriter{console: write, fallback: file}
}

// sshPairConsoleWords is the UTF-16 text WriteConsoleW receives. The QR's
// half-block characters (U+2588, U+2580, U+2584) are single UTF-16 units.
func sshPairConsoleWords(text string) []uint16 {
	return utf16.Encode([]rune(text))
}

// writeConsoleW writes text to a console as UTF-16, in as many calls as the
// console needs: a QR block is several kilobytes and WriteConsoleW may take only
// part of it.
func writeConsoleW(handle windows.Handle, text string) error {
	words := sshPairConsoleWords(text)
	for len(words) > 0 {
		var written uint32
		if err := windows.WriteConsole(handle, &words[0], uint32(len(words)), &written, nil); err != nil {
			return err
		}
		if written == 0 {
			return errors.New("ssh_pair_console_write_failed")
		}
		words = words[written:]
	}
	return nil
}

// localSSHPins computes the SHA256 fingerprints of the host public keys sshd
// generated, i.e. the same values ssh-keyscan would report on Unix. The files
// are the fast path, but ProgramData\ssh is readable only by an elevated
// token, so an administrator's normal window falls back to asking the local
// sshd with the OpenSSH client's ssh-keyscan, which yields the same pins.
func localSSHPins(port int) ([]string, error) {
	dir := sshdConfigDirectory()
	pins := []string{}
	seen := map[string]bool{}
	for _, name := range sshPairHostKeyFiles {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || len(data) > 16384 || strings.ContainsRune(string(data), 0) {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(string(data)))
		if len(fields) < 2 {
			continue
		}
		blob, err := base64.StdEncoding.Strict().DecodeString(fields[1])
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
	if len(pins) > 0 && len(pins) <= 4 {
		return pins, nil
	}
	return sshKeyscanPins(port)
}

// sshKeyscanBinary is the Windows OpenSSH client's scanner: PATH first, then
// the path the optional OpenSSH Client feature installs to.
func sshKeyscanBinary() string {
	if path, err := exec.LookPath("ssh-keyscan.exe"); err == nil {
		return path
	}
	if root := os.Getenv("SystemRoot"); root != "" {
		candidate := filepath.Join(root, "System32", "OpenSSH", "ssh-keyscan.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// sshKeyscanPins is the fallback for a token that may not read the host key
// files. It never runs on a machine without the OpenSSH client.
func sshKeyscanPins(port int) ([]string, error) {
	binary := sshKeyscanBinary()
	if binary == "" {
		return nil, errors.New("ssh_pair_local_ssh_unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "-T", "3", "-p", fmt.Sprint(port), "-t", "ed25519,ecdsa,rsa", "127.0.0.1").Output()
	if err != nil || len(output) > 16384 {
		return nil, errors.New("ssh_pair_local_ssh_unavailable")
	}
	return sshPinsFromKeyscanOutput(output)
}
