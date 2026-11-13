//go:build linux || darwin

package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fakeRuntimeDir(t *testing.T) string {
	t.Helper()
	// Short and symlink-free: macOS temp dirs exceed the socket path limit.
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	run, err := os.MkdirTemp(root, "rt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(run) })
	os.Chmod(run, 0700)
	old := runtimeDir
	runtimeDir = func() string { return run }
	t.Cleanup(func() { runtimeDir = old })
	return run
}

func echoOnce(ln net.Listener) {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("x"))
			c.Close()
		}
	}()
}

func dialRead(t *testing.T, dir string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := dialLocal(ctx, dir)
	if err != nil {
		return err
	}
	defer c.Close()
	b, err := io.ReadAll(c)
	if err == nil && string(b) != "x" {
		t.Fatal(string(b))
	}
	return err
}

// Sandboxed hooks (DSH with bwrap) see an empty /tmp but the runtime directory.
func TestRuntimeDirSocket(t *testing.T) {
	run := fakeRuntimeDir(t)
	dir := t.TempDir()
	ln, err := listenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	echoOnce(ln)
	parents, _ := socketDirs(dir)
	if len(parents) != 2 || filepath.Dir(parents[0]) != run {
		t.Fatal(parents)
	}
	for _, p := range parents {
		c, err := net.Dial("unix", filepath.Join(p, "agent.sock"))
		if err != nil {
			t.Fatal(p, err)
		}
		if b, _ := io.ReadAll(c); string(b) != "x" {
			t.Fatal(p)
		}
		c.Close()
	}
	if err = dialRead(t, dir); err != nil {
		t.Fatal(err)
	}
	ln.Close()
	for _, p := range parents {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatal("socket dir left behind", p)
		}
	}
	if _, err = ln.Accept(); err == nil {
		t.Fatal("accept after close")
	}
}

// An older daemon only listens under /tmp; new hooks still reach it.
func TestDialFallsBackToTmp(t *testing.T) {
	dir := t.TempDir()
	tmp, err := socketDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := listenAt(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	echoOnce(ln)
	fakeRuntimeDir(t)
	if err = dialRead(t, dir); err != nil {
		t.Fatal(err)
	}
}

// An unusable runtime directory never prevents serving under /tmp.
func TestRuntimeDirOptional(t *testing.T) {
	run := fakeRuntimeDir(t)
	dir := t.TempDir()
	os.Chmod(run, 0500)
	defer os.Chmod(run, 0700)
	ln, err := listenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	echoOnce(ln)
	if err = dialRead(t, dir); err != nil {
		t.Fatal(err)
	}
}
