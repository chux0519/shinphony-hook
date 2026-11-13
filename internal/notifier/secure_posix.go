//go:build darwin || linux

package notifier

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func checkParents(path string) error {
	// Resolve platform aliases such as macOS /var -> /private/var only outside
	// the private store; an owned writable ancestor must not be group/world writable.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return errUnsafe
	}
	for p := resolved; ; p = filepath.Dir(p) {
		i, err := os.Lstat(p)
		if err != nil || !i.IsDir() {
			return errUnsafe
		}
		if i.Mode().Perm()&0022 != 0 && i.Mode()&os.ModeSticky == 0 {
			return errUnsafe
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

// Agent directories often inherit umask 0002 (0775). An owned 0700 HOME
// prevents other users from traversing them. This exception applies only to
// agent config parents, never the credential store's strict 0700/0600 rules.
func checkConfigParents(path string) error {
	if checkParents(path) == nil {
		return nil
	}
	home, e := os.UserHomeDir()
	if e != nil {
		return errUnsafe
	}
	home, e = filepath.EvalSymlinks(home)
	if e != nil {
		return errUnsafe
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return errUnsafe
	}
	if resolved != home && !strings.HasPrefix(resolved, home+string(os.PathSeparator)) {
		return errUnsafe
	}
	if e = checkPrivate(home, true); e != nil {
		return e
	}
	for p := resolved; p != home; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() {
			return errUnsafe
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(os.Geteuid()) {
			return errUnsafe
		}
	}
	return nil
}
func checkPrivate(path string, dir bool) error {
	if err := checkParents(filepath.Dir(path)); err != nil {
		return err
	}
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || i.Mode()&os.ModeSymlink != 0 || i.Mode().Perm()&0077 != 0 {
		return errUnsafe
	}
	if dir {
		if !i.IsDir() {
			return errUnsafe
		}
	} else if !i.Mode().IsRegular() || st.Nlink != 1 {
		return errUnsafe
	}
	return nil
}
func makePrivateDir(path string) error { return os.Mkdir(path, 0700) }
func createPrivate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}
