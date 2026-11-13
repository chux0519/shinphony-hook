//go:build windows

package notifier

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

func currentSID() (*windows.SID, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	return u.User.Sid, nil
}
func checkConfigParents(path string) error { return checkParents(path) }
func privateAttributes() (*windows.SecurityAttributes, error) {
	sid, e := currentSID()
	if e != nil {
		return nil, e
	}
	sd, e := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;;FA;;;" + sid.String() + ")")
	if e != nil {
		return nil, e
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}
func checkParents(path string) error {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		ptr, e := windows.UTF16PtrFromString(p)
		if e != nil {
			return errUnsafe
		}
		a, e := windows.GetFileAttributes(ptr)
		if e != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || a&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return errUnsafe
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func checkPrivate(path string, dir bool) error {
	if e := checkParents(filepath.Dir(path)); e != nil {
		return e
	}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return errUnsafe
	}
	a, e := windows.GetFileAttributes(p)
	if e != nil {
		return e
	}
	if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (a&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != dir {
		return errUnsafe
	}
	sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return errUnsafe
	}
	sid, e := currentSID()
	if e != nil {
		return errUnsafe
	}
	owner, _, e := sd.Owner()
	if e != nil || !owner.Equals(sid) {
		return errUnsafe
	}
	// Only accept the exact protected current-user-only descriptor we create.
	expected, e := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;;FA;;;" + sid.String() + ")")
	if e != nil || sd.String() != expected.String() {
		return errUnsafe
	}
	return nil
}
func makePrivateDir(path string) error {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	a, e := privateAttributes()
	if e != nil {
		return e
	}
	return windows.CreateDirectory(p, a)
}
func createPrivate(path string) (*os.File, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	a, e := privateAttributes()
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_WRITE, 0, a, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), path), nil
}
