//go:build windows

package main

// Windows storage for `keys`. The target file depends on the account: a local
// administrator's key goes to C:\ProgramData\ssh\administrators_authorized_keys
// (Administrators and SYSTEM only, no inheritance), everyone else's to
// %USERPROFILE%\.ssh\authorized_keys. Nothing is ever truncated: a temp file in
// the same directory replaces the target with MoveFileEx, and a snapshot check
// refuses to overwrite an edit made in between.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsKeyRequiredSDDL is the ACL OpenSSH requires on
// administrators_authorized_keys: owner and full access for Administrators and
// SYSTEM only, inherited ACEs dropped.
const windowsKeyRequiredSDDL = "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"

// errSSHPairNeedsAdmin is the one reason pairing raises a second UAC prompt: an
// administrator's key file lives in ProgramData\ssh and only an elevated
// process may write it. It is a sentinel so `pair` can tell this refusal apart
// from a real failure instead of matching the message.
var errSSHPairNeedsAdmin = errors.New("ssh_pair_needs_admin")

// sshKeyStat is Windows' file identity: the volume and file index, so a replace
// between read and write is detected.
type sshKeyStat struct {
	Volume uint32
	Index  uint64
}

func keysPrivilegeCheck() error {
	// Administrators install into ProgramData\ssh and need elevation; that check
	// lives in the store so `keys list` still works for other accounts.
	return nil
}

func windowsFileStat(info windows.ByHandleFileInformation) sshKeyStat {
	return sshKeyStat{
		Volume: info.VolumeSerialNumber,
		Index:  uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
	}
}

func sameSSHKeySnapshot(a, b sshKeySnapshot) bool {
	if (a.stat == nil) != (b.stat == nil) {
		return false
	}
	return string(a.data) == string(b.data) && (a.stat == nil || *a.stat == *b.stat)
}

// windowsSIDAllowed reports whether the SID is in the allowed list.
func windowsSIDAllowed(sid *windows.SID, allowed []*windows.SID) bool {
	for _, candidate := range allowed {
		if candidate != nil && sid.Equals(candidate) {
			return true
		}
	}
	return false
}

// windowsWriteMask is what makes an ACE a writing grant: anything that can
// change, replace or delete the object.
const windowsWriteMask = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | windows.WRITE_DAC |
	windows.WRITE_OWNER | windows.DELETE | windows.GENERIC_WRITE | windows.GENERIC_ALL

// windowsACE is one entry of a DACL, decoded generically so deny and object
// ACEs are not misread as ACCESS_ALLOWED_ACE.
type windowsACE struct {
	Type        byte
	Flags       byte
	Mask        windows.ACCESS_MASK
	SID         *windows.SID
	InheritOnly bool
}

func windowsReadDACL(acl *windows.ACL) ([]windowsACE, error) {
	entries := make([]windowsACE, 0, acl.AceCount)
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		// GetAce only returns the allowed-ACE shape; allowed and denied ACEs share
		// the header, mask and SID layout, so the cast below reads both.
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil {
			return nil, err
		}
		entry := windowsACE{Type: ace.Header.AceType, Flags: ace.Header.AceFlags, Mask: ace.Mask}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			entry.SID = (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		}
		entry.InheritOnly = entry.Flags&windows.INHERIT_ONLY_ACE != 0
		entries = append(entries, entry)
	}
	return entries, nil
}

// windowsACLIsSafe is OpenSSH's StrictModes rule on Windows: the owner must be
// one of allowed (the account, SYSTEM, Administrators) and no other principal
// may hold a writing grant. Read-only access for anyone else is fine, which is
// what a profile-like %USERPROFILE%\.ssh inherits. On a directory an inheritable
// writing ACE counts too, because it reaches the key file inside it.
func windowsACLIsSafe(path string, allowed []*windows.SID, dir bool) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, errors.New("keys_unsafe_file_permissions")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !windowsSIDAllowed(owner, allowed) {
		return false, nil
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return false, errors.New("keys_unsafe_file_permissions")
	}
	entries, err := windowsReadDACL(acl)
	if err != nil {
		return false, errors.New("keys_unsafe_file_permissions")
	}
	for _, entry := range entries {
		// A deny ACE cannot grant access, and an inherit-only ACE does not apply to
		// this object; children are checked when they are read.
		if entry.Type == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if entry.InheritOnly && !dir {
			continue
		}
		if entry.Type != windows.ACCESS_ALLOWED_ACE_TYPE || entry.SID == nil {
			// Object or callback ACEs are never written by sshd or this installer.
			return false, nil
		}
		if entry.Mask&windowsWriteMask != 0 && !windowsSIDAllowed(entry.SID, allowed) {
			return false, nil
		}
	}
	return true, nil
}

// windowsACLAllowsOnly reports whether the object's owner and every ACE on it
// belong to the allowed SIDs. The administrator key file uses this stricter
// rule: Administrators and SYSTEM only, no inheritance.
func windowsACLAllowsOnly(path string, allowed []*windows.SID) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, errors.New("keys_unsafe_file_permissions")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !windowsSIDAllowed(owner, allowed) {
		return false, nil
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return false, errors.New("keys_unsafe_file_permissions")
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, (**windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(&ace))); err != nil {
			return false, errors.New("keys_unsafe_file_permissions")
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false, nil
		}
		if !windowsSIDAllowed((*windows.SID)(unsafe.Pointer(&ace.SidStart)), allowed) {
			return false, nil
		}
	}
	return true, nil
}

// windowsACLIsProtected reports whether the object's DACL is protected, i.e.
// it does not inherit entries from its parent. The administrator key file must
// not inherit anything.
func windowsACLIsProtected(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, errors.New("keys_unsafe_file_permissions")
	}
	control, _, err := sd.Control()
	if err != nil {
		return false, errors.New("keys_unsafe_file_permissions")
	}
	return control&windows.SE_DACL_PROTECTED != 0, nil
}

// windowsAdminKeyACLIsStrict is the administrator rule: Administrators and
// SYSTEM only, and the DACL must not inherit anything.
func windowsAdminKeyACLIsStrict(path string, allowed []*windows.SID) (bool, error) {
	ok, err := windowsACLAllowsOnly(path, allowed)
	if err != nil || !ok {
		return false, err
	}
	return windowsACLIsProtected(path)
}

// windowsAdminKeyACLs restricts an administrators_authorized_keys (and the
// directory holding it) to Administrators and SYSTEM, dropping inheritance.
func windowsAdminKeyACLs(path string) error {
	sd, err := windows.SecurityDescriptorFromString(windowsKeyRequiredSDDL)
	if err != nil {
		return errors.New("keys_unsafe_file_permissions")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return errors.New("keys_unsafe_file_permissions")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return errors.New("keys_unsafe_file_permissions")
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
	if err != nil {
		return errors.New("keys_unsafe_file_permissions")
	}
	return nil
}

// windowsAdminSecurityAttributes is the creation ACL for a file that holds an
// administrator's key.
func windowsAdminSecurityAttributes() (*windows.SecurityAttributes, error) {
	sd, err := windows.SecurityDescriptorFromString(windowsKeyRequiredSDDL)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

// windowsSSHKeyStore is the Windows implementation of sshKeyStore. keysFile is
// the account-specific name the shared contract's "authorized_keys" maps to:
// administrators_authorized_keys for an administrator, authorized_keys
// otherwise.
type windowsSSHKeyStore struct {
	dir      string
	keysFile string
	admin    bool
	elevated bool
}

// sshKeyStoreTarget resolves this account's key directory and file name. Tests
// replace it so the shared state machine can run against a temporary directory.
var sshKeyStoreTarget = windowsKeyDirectoryForAccount

func openSSHKeyStore(home string, create bool) (sshKeyStore, error) {
	dir, keysFile, admin := sshKeyStoreTarget(home)
	// administrators_authorized_keys lives in ProgramData\ssh, which a
	// non-elevated administrator token can neither read nor write.
	if admin && !windowsIsElevated() {
		return nil, errSSHPairNeedsAdmin
	}
	_, statErr := os.Stat(dir)
	switch {
	case statErr == nil:
		if err := windowsCheckKeyDirectory(dir, admin); err != nil {
			return nil, err
		}
	case errors.Is(statErr, os.ErrNotExist):
		// A missing .ssh is not an error for list or preview: nothing is created.
		if !create {
			return nil, os.ErrNotExist
		}
		if err := windowsPrepareKeyDirectory(dir, admin); err != nil {
			return nil, err
		}
		if err := windowsCheckKeyDirectory(dir, admin); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("keys_unsafe_directory")
	}
	return &windowsSSHKeyStore{dir: dir, keysFile: keysFile, admin: admin, elevated: windowsIsElevated()}, nil
}

// windowsCheckKeyDirectory validates an existing key directory: not a reparse
// point, owned as expected, with no foreign writer.
func windowsCheckKeyDirectory(dir string, admin bool) error {
	if err := noReparse(dir); err != nil {
		return errors.New("keys_unsafe_directory")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return errors.New("keys_unsafe_directory")
	}
	allowed, err := windowsKeyAllowedSIDs(admin)
	if err != nil {
		return errors.New("keys_unsafe_directory")
	}
	ok, err := windowsACLIsSafe(dir, allowed, true)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("keys_unsafe_directory")
	}
	return nil
}

// windowsKeyAllowedSIDs is who may own and write the SSH directory and keys
// file: the account, SYSTEM and Administrators for a user, SYSTEM and
// Administrators for the shared administrator file.
func windowsKeyAllowedSIDs(admin bool) ([]*windows.SID, error) {
	system, _ := windowsSystemSID()
	adminSID, _ := windowsAdministratorsSID()
	if admin {
		return []*windows.SID{system, adminSID}, nil
	}
	return windowsUserAllowedSIDs()
}

// windowsPrepareKeyDirectory creates the key directory when it is missing and
// checks that an existing one is not an unsafe location for sshd.
func windowsPrepareKeyDirectory(dir string, admin bool) error {
	if err := noReparse(filepath.Dir(dir)); err != nil {
		return errors.New("keys_unsafe_directory")
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return errors.New("keys_unsafe_directory")
	}
	sa, err := windowsKeyFileAttributes(admin)
	if err != nil {
		return errors.New("keys_unsafe_directory")
	}
	// An existing directory keeps the ACL OpenSSH gave it; only a directory this
	// installer creates gets the required one.
	_, existing := os.Stat(dir)
	if err = windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return errSSHPairNeedsAdmin
		}
		return errors.New("keys_directory_create_failed")
	}
	if admin {
		if existing == nil {
			return nil
		}
		return windowsAdminKeyACLs(dir)
	}
	return nil
}

// windowsUserAllowedSIDs is who may hold a user's SSH directory and key file:
// the account, SYSTEM and Administrators, which is exactly what sshd accepts.
func windowsUserAllowedSIDs() ([]*windows.SID, error) {
	me, err := currentSID()
	if err != nil {
		return nil, err
	}
	system, _ := windowsSystemSID()
	admin, _ := windowsAdministratorsSID()
	return []*windows.SID{me, system, admin}, nil
}

// storeName maps the shared contract's keys file name to this account's file.
func (s *windowsSSHKeyStore) storeName(name string) string {
	if name == "authorized_keys" && s.keysFile != "" {
		return s.keysFile
	}
	return name
}

func (s *windowsSSHKeyStore) read(name string) (sshKeySnapshot, error) {
	path := filepath.Join(s.dir, s.storeName(name))
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return sshKeySnapshot{}, nil
		}
		return sshKeySnapshot{}, errors.New("keys_unsafe_file")
	}
	if err := noReparse(path); err != nil {
		return sshKeySnapshot{}, errors.New("keys_unsafe_file")
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return sshKeySnapshot{}, errors.New("keys_unsafe_file")
	}
	handle, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return sshKeySnapshot{}, errSSHPairNeedsAdmin
		}
		return sshKeySnapshot{}, errors.New("keys_unsafe_file")
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil || info.NumberOfLinks != 1 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return sshKeySnapshot{}, errors.New("keys_unsafe_file_permissions")
	}
	allowed, err := windowsKeyAllowedSIDs(s.admin)
	if err != nil {
		windows.CloseHandle(handle)
		return sshKeySnapshot{}, errors.New("keys_home_unavailable")
	}
	ok, err := windowsACLIsSafe(path, allowed, false)
	if s.admin {
		ok, err = windowsAdminKeyACLIsStrict(path, allowed)
	}
	if err != nil {
		windows.CloseHandle(handle)
		return sshKeySnapshot{}, err
	}
	if !ok {
		windows.CloseHandle(handle)
		return sshKeySnapshot{}, errors.New("keys_unsafe_file_permissions")
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, sshKeyFileLimit+1))
	if err != nil || len(data) > sshKeyFileLimit {
		return sshKeySnapshot{}, errors.New("keys_file_unreadable")
	}
	stat := windowsFileStat(info)
	return sshKeySnapshot{data: data, stat: &stat}, nil
}

// write creates the replacement in the same directory and swaps it in with
// MoveFileEx, so the key file is never truncated and never loses a line.
func (s *windowsSSHKeyStore) write(name string, data []byte, expected sshKeySnapshot) error {
	if len(data) > sshKeyFileLimit {
		return errors.New("keys_file_too_large")
	}
	if s.admin && !s.elevated {
		return errSSHPairNeedsAdmin
	}
	// An existing administrators_authorized_keys keeps its ACL unless it is
	// looser than sshd allows; then it is narrowed to Administrators and SYSTEM
	// and the change is reported.
	if s.admin {
		if err := s.restrictAdminKeyACL(name); err != nil {
			return err
		}
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	temp := filepath.Join(s.dir, ".shinphony-key-"+hex.EncodeToString(nonce))
	sa, err := windowsKeyFileAttributes(s.admin)
	if err != nil {
		return errors.New("keys_write_failed")
	}
	tempPtr, err := windows.UTF16PtrFromString(temp)
	if err != nil {
		return errors.New("keys_write_failed")
	}
	handle, err := windows.CreateFile(tempPtr, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return errSSHPairNeedsAdmin
		}
		return errors.New("keys_write_failed")
	}
	file := os.NewFile(uintptr(handle), temp)
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(temp)
		return errors.New("keys_write_failed")
	}
	current, err := s.read(name)
	if err != nil {
		os.Remove(temp)
		return err
	}
	if !sameSSHKeySnapshot(current, expected) {
		os.Remove(temp)
		return errors.New("keys_file_changed")
	}
	target, err := windows.UTF16PtrFromString(filepath.Join(s.dir, s.storeName(name)))
	if err != nil {
		os.Remove(temp)
		return errors.New("keys_write_failed")
	}
	if err = windows.MoveFileEx(tempPtr, target, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		os.Remove(temp)
		return errors.New("keys_write_failed")
	}
	// The rename carries the temp file's ACL; state the required one anyway so a
	// replaced administrators file is always exactly as sshd demands.
	if s.admin {
		if err = windowsAdminKeyACLs(filepath.Join(s.dir, s.storeName(name))); err != nil {
			return err
		}
	}
	return nil
}

// restrictAdminKeyACL narrows an existing administrators_authorized_keys that
// grants access to anyone besides the allowed SIDs.
func (s *windowsSSHKeyStore) restrictAdminKeyACL(name string) error {
	path := filepath.Join(s.dir, s.storeName(name))
	if _, err := os.Lstat(path); err != nil {
		return nil
	}
	allowed, err := windowsKeyAllowedSIDs(s.admin)
	if err != nil {
		return err
	}
	ok, err := windowsAdminKeyACLIsStrict(path, allowed)
	if err != nil || ok {
		return err
	}
	if err = windowsAdminKeyACLs(path); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Shinphony: "+s.storeName(name)+" granted access beyond Administrators and SYSTEM; the key file is now restricted to them.")
	return nil
}

// windowsPrepareAdminKeyFile makes administrators_authorized_keys exist with the
// ACL sshd requires, without touching its content: it creates the file (and its
// ProgramData\ssh directory) when missing, and re-states the exact ACL
// otherwise. The elevated pairing window calls it before the key is approved, so
// the later, short elevated `keys install` only has to replace the key file.
func windowsPrepareAdminKeyFile(home string) error {
	store, err := openSSHKeyStore(home, true)
	if err != nil {
		return err
	}
	defer store.close()
	keys, ok := store.(*windowsSSHKeyStore)
	if !ok || !keys.admin {
		return errors.New("keys_prepare_unavailable")
	}
	unlock, err := store.lock()
	if err != nil {
		return err
	}
	defer unlock()
	path := filepath.Join(keys.dir, keys.keysFile)
	_, statErr := os.Lstat(path)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		if err = windowsCreateAdminKeyFile(path); err != nil {
			return err
		}
	case statErr != nil:
		return errors.New("keys_unsafe_file")
	default:
		// An existing file is only re-ACLed when it is the regular file it
		// looks like, never a link to somewhere else.
		if err = noReparse(path); err != nil {
			return errors.New("keys_unsafe_file")
		}
	}
	return windowsAdminKeyACLs(path)
}

// windowsCreateAdminKeyFile creates the empty administrator key file with the
// required owner and ACL in one call, so it never exists with a looser one.
func windowsCreateAdminKeyFile(path string) error {
	sa, err := windowsAdminSecurityAttributes()
	if err != nil {
		return errors.New("keys_write_failed")
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("keys_write_failed")
	}
	handle, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return errSSHPairNeedsAdmin
		}
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			// Something created it in between; the caller re-states the ACL next.
			return nil
		}
		return errors.New("keys_write_failed")
	}
	return windows.CloseHandle(handle)
}

// windowsKeyFileAttributes is the creation ACL for a temp file: the
// Administrators/SYSTEM pair for the shared file, user-only otherwise.
func windowsKeyFileAttributes(admin bool) (*windows.SecurityAttributes, error) {
	if admin {
		return windowsAdminSecurityAttributes()
	}
	return attributes()
}

func (s *windowsSSHKeyStore) close() {}

func (s *windowsSSHKeyStore) lock() (func(), error) {
	path := filepath.Join(s.dir, ".shinphony-keys.lock")
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("keys_lock_failed")
	}
	sa, err := windowsKeyFileAttributes(s.admin)
	if err != nil {
		return nil, errors.New("keys_lock_failed")
	}
	handle, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, errSSHPairNeedsAdmin
		}
		return nil, errors.New("keys_lock_failed")
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil || info.NumberOfLinks != 1 {
		windows.CloseHandle(handle)
		return nil, errors.New("keys_unsafe_lock")
	}
	var overlapped windows.Overlapped
	if err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		windows.CloseHandle(handle)
		return nil, errors.New("keys_busy")
	}
	return func() { windows.CloseHandle(handle) }, nil
}
