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
	owner, _, err := sd.Owner()
	if err != nil || !owner.Equals(sid) {
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
