//go:build darwin || linux

package main

// Unix storage for `keys`: an open descriptor on ~/.ssh with the ownership,
// mode and link checks the installer has always used. The contract itself,
// including the journal's state machine, lives in ssh_keys.go.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// sshKeyStat is Unix's file identity: the inode and device the snapshot came
// from, so a replace between read and write is detected.
type sshKeyStat = unix.Stat_t

func keysPrivilegeCheck() error {
	if os.Geteuid() == 0 {
		return errors.New("keys_root_not_supported")
	}
	return nil
}

func sshKeyDirectory(home string, create bool) (int, error) {
	h, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.New("keys_home_unavailable")
	}
	defer unix.Close(h)
	d, err := unix.Openat(h, ".ssh", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) && create {
		if err = unix.Mkdirat(h, ".ssh", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, errors.New("keys_directory_create_failed")
		}
		d, err = unix.Openat(h, ".ssh", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return -1, os.ErrNotExist
		}
		return -1, errors.New("keys_unsafe_directory")
	}
	var info unix.Stat_t
	if unix.Fstat(d, &info) != nil || info.Uid != uint32(os.Geteuid()) || info.Mode&0777 != 0700 {
		unix.Close(d)
		return -1, errors.New("keys_unsafe_directory_permissions")
	}
	return d, nil
}

func sshKeyRead(dir int, name string) (sshKeySnapshot, error) {
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return sshKeySnapshot{}, nil
	}
	if err != nil {
		return sshKeySnapshot{}, errors.New("keys_unsafe_file")
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Geteuid()) || info.Mode&0777 != 0600 || info.Nlink != 1 {
		return sshKeySnapshot{}, errors.New("keys_unsafe_file_permissions")
	}
	data, err := io.ReadAll(io.LimitReader(f, sshKeyFileLimit+1))
	if err != nil || len(data) > sshKeyFileLimit || bytes.ContainsRune(data, 0) {
		return sshKeySnapshot{}, errors.New("keys_file_unreadable")
	}
	return sshKeySnapshot{data: data, stat: &info}, nil
}

func sameSSHKeySnapshot(a, b sshKeySnapshot) bool {
	if (a.stat == nil) != (b.stat == nil) {
		return false
	}
	return bytes.Equal(a.data, b.data) && (a.stat == nil || a.stat.Ino == b.stat.Ino && a.stat.Dev == b.stat.Dev)
}

// The lock coordinates our writers; re-read also detects external changes since
// the snapshot. No existing file is ever opened for truncation.
func sshKeyWrite(dir int, name string, data []byte, expected sshKeySnapshot) error {
	if len(data) > sshKeyFileLimit {
		return errors.New("keys_file_too_large")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	temp := ".shinphony-key-" + hex.EncodeToString(nonce)
	fd, err := unix.Openat(dir, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("keys_write_failed")
	}
	defer unix.Unlinkat(dir, temp, 0)
	f := os.NewFile(uintptr(fd), temp)
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("keys_write_failed")
	}
	current, err := sshKeyRead(dir, name)
	if err != nil {
		return err
	}
	if !sameSSHKeySnapshot(current, expected) {
		return errors.New("keys_file_changed")
	}
	if err = unix.Renameat(dir, temp, dir, name); err != nil {
		return errors.New("keys_write_failed")
	}
	if err = unix.Fsync(dir); err != nil {
		return errors.New("keys_write_failed")
	}
	return nil
}

// unixSSHKeyStore adapts the descriptor-based helpers to sshKeyStore.
type unixSSHKeyStore struct{ dir int }

func (s *unixSSHKeyStore) read(name string) (sshKeySnapshot, error) {
	return sshKeyRead(s.dir, name)
}
func (s *unixSSHKeyStore) write(name string, data []byte, expected sshKeySnapshot) error {
	return sshKeyWrite(s.dir, name, data, expected)
}
func (s *unixSSHKeyStore) close() {
	if s.dir >= 0 {
		unix.Close(s.dir)
		s.dir = -1
	}
}
func (s *unixSSHKeyStore) lock() (func(), error) {
	lock, err := unix.Openat(s.dir, ".shinphony-keys.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("keys_lock_failed")
	}
	defer unix.Close(lock)
	var li unix.Stat_t
	if unix.Fstat(lock, &li) != nil || li.Mode&unix.S_IFMT != unix.S_IFREG || li.Nlink != 1 || li.Uid != uint32(os.Geteuid()) || li.Mode&0777 != 0600 {
		return nil, errors.New("keys_unsafe_lock")
	}
	if unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, errors.New("keys_busy")
	}
	// The file stays open for the whole critical section; closing releases it.
	return func() { unix.Close(lock) }, nil
}

func openSSHKeyStore(home string, create bool) (sshKeyStore, error) {
	dir, err := sshKeyDirectory(home, create)
	if err != nil {
		return nil, err
	}
	return &unixSSHKeyStore{dir: dir}, nil
}
