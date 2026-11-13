//go:build linux || darwin

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
)

func privatePath(path string, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != dir || (!dir && !info.Mode().IsRegular()) || info.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe_permissions")
	}
	if !dir && st.Nlink != 1 {
		return errors.New("unsafe_links")
	}
	return nil
}
func prepareDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("absolute_state_path_required")
	}
	// Reject redirected or writable ancestors; a private user-owned ancestor
	// protects existing group-writable descendants inside that private home.
	protected := false
	parts := []string{}
	for p := filepath.Dir(dir); p != "/"; p = filepath.Dir(p) {
		parts = append(parts, p)
	}
	for n := len(parts) - 1; n >= 0; n-- {
		s, err := os.Lstat(parts[n])
		if err != nil {
			return err
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe_parent")
		}
		if !protected && s.Mode().Perm()&0022 != 0 && s.Mode()&os.ModeSticky == 0 {
			return errors.New("unsafe_parent")
		}
		if st.Uid == uint32(os.Getuid()) && s.Mode().Perm()&0077 == 0 {
			protected = true
		}
	}
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	return privatePath(dir, true)
}
func lockDir(dir string) (func(), error) {
	path := filepath.Join(dir, "service.lock")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err = privatePath(path, false); err != nil {
		f.Close()
		return nil, err
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("already_running")
	}
	return func() { f.Close() }, nil
}
func privateUmask() error { syscall.Umask(0077); return nil }

// Hooks may run inside an agent's sandbox: DSH's bwrap backend mounts a fresh
// /tmp, while the per-user runtime directory stays visible read-only. Try that
// one first; /tmp remains the default for systems without it.
func dialLocal(ctx context.Context, dir string) (net.Conn, error) {
	parents, err := socketDirs(dir)
	if err != nil {
		return nil, err
	}
	for _, parent := range parents {
		if err = privatePath(parent, true); err != nil {
			continue
		}
		var conn net.Conn
		if conn, err = (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(parent, "agent.sock")); err == nil {
			return conn, nil
		}
	}
	return nil, err
}
func socketDir(dir string) (string, error) {
	root, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return "", err
	}
	return filepath.Join(root, socketName(dir)), nil
}
func socketName(dir string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(dir)))
	return "shinphony-" + strconv.Itoa(os.Getuid()) + "-" + hex.EncodeToString(sum[:8])
}

// runtimeDir is systemd's /run/user/UID when it exists and is private; it is
// looked up by UID rather than $XDG_RUNTIME_DIR, which hooks may not inherit.
var runtimeDir = func() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	p := "/run/user/" + strconv.Itoa(os.Getuid())
	if privatePath(p, true) != nil {
		return ""
	}
	return p
}

// socketDirs lists the candidate socket directories, preferred first.
func socketDirs(dir string) ([]string, error) {
	tmp, err := socketDir(dir)
	if err != nil {
		return nil, err
	}
	if run := runtimeDir(); run != "" {
		return []string{filepath.Join(run, socketName(dir)), tmp}, nil
	}
	return []string{tmp}, nil
}

type localListener struct {
	net.Listener
	parent string
}

func (l *localListener) Close() error { err := l.Listener.Close(); os.Remove(l.parent); return err }

// listenLocal always listens under /tmp; the runtime-directory socket is an
// extra path for sandboxed hooks, so failing to create it is not fatal.
func listenLocal(dir string) (net.Listener, error) {
	parents, err := socketDirs(dir)
	if err != nil {
		return nil, err
	}
	primary, err := listenAt(parents[len(parents)-1])
	if err != nil {
		return nil, err
	}
	if len(parents) == 1 {
		return primary, nil
	}
	extra, err := listenAt(parents[0])
	if err != nil {
		return primary, nil
	}
	return mergeListeners(primary, extra), nil
}
func listenAt(parent string) (net.Listener, error) {
	if err := prepareDir(parent); err != nil {
		return nil, err
	}
	socket := filepath.Join(parent, "agent.sock")
	if s, err := os.Lstat(socket); err == nil {
		if s.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("unsafe_socket_path")
		}
		if err = os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, err
	}
	return &localListener{ln, parent}, nil
}

// multiListener accepts from several listeners; Addr reports the first.
type multiListener struct {
	all   []net.Listener
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func mergeListeners(ls ...net.Listener) net.Listener {
	m := &multiListener{all: ls, conns: make(chan net.Conn), done: make(chan struct{})}
	for _, l := range ls {
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					var ne net.Error
					if errors.As(err, &ne) && ne.Timeout() {
						continue
					}
					return
				}
				select {
				case m.conns <- c:
				case <-m.done:
					c.Close()
					return
				}
			}
		}(l)
	}
	return m
}
func (m *multiListener) Accept() (net.Conn, error) {
	select {
	case c := <-m.conns:
		return c, nil
	case <-m.done:
		return nil, net.ErrClosed
	}
}
func (m *multiListener) Close() error {
	var err error
	m.once.Do(func() {
		close(m.done)
		for _, l := range m.all {
			if e := l.Close(); err == nil {
				err = e
			}
		}
	})
	return err
}
func (m *multiListener) Addr() net.Addr { return m.all[0].Addr() }
