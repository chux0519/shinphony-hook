//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Elevated SSH tokens can otherwise create SQLite files owned by Administrators.
// Set only this process token's default owner, never weaken an existing ACL.
func privateUmask() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	owner := struct{ Owner *windows.SID }{user.User.Sid}
	return windows.SetTokenInformation(token, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner)))
}
func currentSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}
func attributes() (*windows.SecurityAttributes, error) {
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;OICI;FA;;;" + sid.String() + ")")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}
func noReparse(path string) error {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		ptr, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return err
		}
		a, err := windows.GetFileAttributes(ptr)
		if err != nil {
			return err
		}
		if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("unsafe_reparse_path")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

// windowsPrivateOwnerAccepted reports whether an owner SID is acceptable for a
// path only this account may use. An elevated administrator process creates
// objects owned by BUILTIN\Administrators rather than by the user (that is the
// default owner of an elevated token), so for an account that is itself an
// administrator the group owner is the same trust boundary: such an account can
// take ownership of anything anyway. A standard user's path must stay owned by
// the user, and SYSTEM or another account never passes.
func windowsPrivateOwnerAccepted(owner, account *windows.SID, administrator bool) bool {
	if owner == nil || account == nil {
		return false
	}
	if owner.Equals(account) {
		return true
	}
	if !administrator {
		return false
	}
	administrators, err := windowsAdministratorsSID()
	return err == nil && owner.Equals(administrators)
}

// windowsAdoptPrivateOwner hands a path back to this account when an elevated
// administrator process created it under BUILTIN\Administrators. Changing an
// owner needs SeRestorePrivilege, so the privilege is enabled for this one call
// and the token is put back afterwards; only an elevated token can enable it.
// A refusal is not an error: the owner rule already accepted the path and the
// DACL stays this account's.
func windowsAdoptPrivateOwner(path string, account *windows.SID) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &token); err != nil {
		return
	}
	defer token.Close()
	name, err := windows.UTF16PtrFromString("SeRestorePrivilege")
	if err != nil {
		return
	}
	var luid windows.LUID
	if err = windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return
	}
	enable := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	var previous windows.Tokenprivileges
	if err = windows.AdjustTokenPrivileges(token, false, &enable, 0, &previous, nil); err != nil {
		return
	}
	defer func() { _ = windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil) }()
	_ = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, account, nil, nil, nil)
}
func privatePath(path string, dir bool) error {
	if err := noReparse(path); err != nil {
		return err
	}
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if s.IsDir() != dir || (!dir && !s.Mode().IsRegular()) {
		return errors.New("unsafe_path")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	sid, err := currentSID()
	if err != nil {
		return err
	}
	// The owner rule accepts Administrators for an administrator account; the
	// DACL below still has to be this account's alone, with no inherited entry.
	owner, _, err := sd.Owner()
	if err != nil || !windowsPrivateOwnerAccepted(owner, sid, windowsIsAdministrator()) {
		return errors.New("unsafe_owner")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return errors.New("unsafe_acl")
	}
	for n := uint32(0); n < uint32(acl.AceCount); n++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, n, (**windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(&ace))); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			return errors.New("unsafe_acl")
		}
	}
	if !dir {
		p, _ := windows.UTF16PtrFromString(path)
		h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(h)
		var info windows.ByHandleFileInformation
		if err = windows.GetFileInformationByHandle(h, &info); err != nil {
			return err
		}
		if info.NumberOfLinks != 1 {
			return errors.New("unsafe_links")
		}
	}
	if !owner.Equals(sid) {
		// Accepted because this account is an administrator; hand it back so a
		// later non-elevated run sees exactly what it always expects.
		windowsAdoptPrivateOwner(path, sid)
	}
	return nil
}
func prepareDir(dir string) error {
	if !filepath.IsAbs(dir) || strings.HasPrefix(dir, `\\`) {
		return errors.New("local_absolute_path_required")
	}
	if err := noReparse(filepath.Dir(dir)); err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	a, err := attributes()
	if err != nil {
		return err
	}
	if err = windows.CreateDirectory(p, a); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return privatePath(dir, true)
}
func lockDir(dir string) (func(), error) {
	p, err := windows.UTF16PtrFromString(filepath.Join(dir, "service.lock"))
	if err != nil {
		return nil, err
	}
	a, err := attributes()
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, a, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	if err = privatePath(filepath.Join(dir, "service.lock"), false); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	var ov windows.Overlapped
	if err = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov); err != nil {
		windows.CloseHandle(h)
		return nil, errors.New("already_running")
	}
	return func() { windows.CloseHandle(h) }, nil
}

// lockFilePath takes an exclusive lock on one private file without waiting.
// Closing the handle releases it; the file itself stays, so two callers never
// lock different files for the same name.
func lockFilePath(path string) (func(), error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	a, err := attributes()
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, a, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	if err = privatePath(path, false); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	var ov windows.Overlapped
	if err = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov); err != nil {
		windows.CloseHandle(h)
		return nil, errRefreshBusy
	}
	return func() { windows.CloseHandle(h) }, nil
}
func pipePath(dir string) string {
	sid, _ := currentSID()
	sum := sha256.Sum256([]byte(sid.String() + ":" + strings.ToLower(filepath.Clean(dir))))
	return `\\.\pipe\shinphony-agent-` + hex.EncodeToString(sum[:16])
}
func listenLocal(dir string) (net.Listener, error) {
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(pipePath(dir), &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + sid.String() + ")", InputBufferSize: 4096, OutputBufferSize: 4096})
}
func dialLocal(ctx context.Context, dir string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, pipePath(dir))
}
