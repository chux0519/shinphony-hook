//go:build windows

package main

// The QR writer: a console handle must be written through WriteConsoleW so the
// half-block characters render whatever code page the console uses (a code page
// 936 console showed them as mojibake when the bytes went through WriteFile),
// and anything that is not a console must get UTF-8 bytes.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// sshPairQRFixture is what pair prints: ASCII prompts plus the QR itself.
const sshPairQRFixture = "\n" + sshPairQRPrompt + "\n" + "█▀▄\n█  █\n▄▄▄\nPrivate pairing link:\nshinphony://ssh-pair#abc\n"

func TestSSHPairWriterUsesTheConsolePath(t *testing.T) {
	var consoleText string
	fallback := &bytes.Buffer{}
	writer := sshPairWriter{
		console:  func(text string) error { consoleText += text; return nil },
		fallback: fallback,
	}
	n, err := writer.Write([]byte(sshPairQRFixture))
	if err != nil || n != len(sshPairQRFixture) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if consoleText != sshPairQRFixture {
		t.Fatalf("console received %q", consoleText)
	}
	if fallback.Len() != 0 {
		t.Fatal("a console write must not also write UTF-8 bytes")
	}
}

func TestSSHPairWriterFallsBackToUTF8Bytes(t *testing.T) {
	fallback := &bytes.Buffer{}
	writer := sshPairWriter{fallback: fallback} // no console: a pipe or a pty
	n, err := writer.Write([]byte(sshPairQRFixture))
	if err != nil || n != len(sshPairQRFixture) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if fallback.String() != sshPairQRFixture {
		t.Fatalf("fallback received %q", fallback.String())
	}
	if !bytes.Contains(fallback.Bytes(), []byte("█")) {
		t.Fatal("the UTF-8 encoding of the half blocks must be kept")
	}
}

// A console handle that rejects the call (for example one that was closed) still
// gets the bytes rather than losing the QR line.
func TestSSHPairWriterFallsBackWhenTheConsoleRejects(t *testing.T) {
	fallback := &bytes.Buffer{}
	writer := sshPairWriter{
		console:  func(string) error { return errors.New("ssh_pair_console_write_failed") },
		fallback: fallback,
	}
	if _, err := writer.Write([]byte("█\n")); err != nil {
		t.Fatal(err)
	}
	if fallback.String() != "█\n" {
		t.Fatalf("fallback received %q", fallback.String())
	}
}

func TestSSHPairConsoleWordsAreUTF16(t *testing.T) {
	words := sshPairConsoleWords("█▀\n")
	want := []uint16{0x2588, 0x2580, 0x000a}
	if len(words) != len(want) {
		t.Fatalf("words = %#v, want %#v", words, want)
	}
	for i := range want {
		if words[i] != want[i] {
			t.Fatalf("words = %#v, want %#v", words, want)
		}
	}
	// A character outside the BMP still encodes as a surrogate pair.
	if got := sshPairConsoleWords("\U0001F600"); len(got) != 2 {
		t.Fatalf("surrogate pair = %#v", got)
	}
}

// A file handle is not a console, so the writer must take the byte path.
func TestNewSSHPairWriterOnAPipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-console.txt")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var mode uint32
	if windows.GetConsoleMode(windows.Handle(file.Fd()), &mode) == nil {
		t.Skip("this handle is a console")
	}
	writer := newSSHPairWriter(file)
	if typed, ok := writer.(sshPairWriter); !ok || typed.console != nil {
		t.Fatal("a file handle must not use the console path")
	}
	if _, err := writer.Write([]byte("█\n")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || !strings.HasPrefix(string(data), "█") {
		t.Fatalf("file = %q, %v", data, err)
	}
}
