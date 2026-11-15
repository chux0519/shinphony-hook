//go:build windows

package main

// The Windows key storage, tested against a temporary directory: path choice,
// append-without-loss (install twice, revoke twice), the installer lock, the ACL
// rules and the elevation gate. The shared state machine is the same one the
// Unix tests exercise in ssh_keys_unix_test.go.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// useKeyStoreAt points the account's key target at dir for one test.
func useKeyStoreAt(t *testing.T, dir, keysFile string) {
	t.Helper()
	previous := sshKeyStoreTarget
	sshKeyStoreTarget = func(string) (string, string, bool) {
		return dir, keysFile, false
	}
	t.Cleanup(func() { sshKeyStoreTarget = previous })
}

// useTempKeyStore is useKeyStoreAt on a directory whose ACL looks like the one
// Windows puts on a user profile.
func useTempKeyStore(t *testing.T, keysFile string) string {
	t.Helper()
	dir := profileLikeDir(t)
	useKeyStoreAt(t, dir, keysFile)
	return dir
}

// profileLikeDir is a directory with the ACL a normal %USERPROFILE%\.ssh
// inherits: owned by the account, full access for the account, SYSTEM and
// Administrators, no inheritance. %TEMP% cannot be used as is: on a real machine
// it also grants Modify to a sandbox group, which must fail (that is the
// negative test).
func profileLikeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	me, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	sddl := "O:" + me.String() + "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;" + me.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
	if err != nil {
		t.Skipf("cannot give the test directory a profile-like ACL: %v", err)
	}
	return dir
}

func TestWindowsKeyFileChoice(t *testing.T) {
	home := t.TempDir()
	dir, file, admin := windowsKeyDirectoryForAccount(home)
	if admin {
		if dir != sshdConfigDirectory() || file != "administrators_authorized_keys" {
			t.Fatalf("administrator target = %q/%q", dir, file)
		}
	} else {
		if dir != filepath.Join(home, ".ssh") || file != "authorized_keys" {
			t.Fatalf("user target = %q/%q", dir, file)
		}
	}
	if admin != windowsIsAdministrator() {
		t.Fatal("the file choice must follow Administrators membership")
	}
	if want := filepath.Join(dir, file); describeKeyTarget(home) != want {
		t.Fatalf("describeKeyTarget = %q, want %q", describeKeyTarget(home), want)
	}
}

func TestWindowsKeyInstallPreservesAndRevokesOnlyOwnedLine(t *testing.T) {
	dir := useTempKeyStore(t, "administrators_authorized_keys")
	path := filepath.Join(dir, "administrators_authorized_keys")
	original := "# user notes\r\nssh-ed25519 AAAA existing-device"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	req := keyRequest()
	for range 2 {
		if _, err := manageSSHKey(t.TempDir(), "install", req); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := req.PublicKey + " shinphony:" + req.ID + "\n"
	if string(data) != original+"\n"+line {
		t.Fatalf("existing content changed or duplicate key: %q", data)
	}
	for range 2 {
		if _, err := manageSSHKey(t.TempDir(), "revoke", sshKeyRequest{ID: req.ID}); err != nil {
			t.Fatal(err)
		}
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original+"\n" {
		t.Fatalf("removed unrelated content: %q", data)
	}
	// The journal records the final state, so `keys list` can report it.
	list, err := manageSSHKey(t.TempDir(), "list", sshKeyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	records := list.(map[string]any)["keys"].([]sshKeyRecord)
	if len(records) != 1 || records[0].State != "revoked" || records[0].ID != req.ID {
		t.Fatalf("journal after revoke = %+v", records)
	}
}

func TestWindowsKeyStoreRefusesAnUnsafeACL(t *testing.T) {
	dir := useTempKeyStore(t, "authorized_keys")
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte("existing\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Everyone may write it: sshd would refuse, and so does the installer.
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_WRITE | windows.GENERIC_READ | windows.DELETE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}
	if acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, dacl); err == nil {
		if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			t.Skipf("cannot loosen the ACL for the test: %v", err)
		}
	} else if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Skipf("cannot loosen the ACL for the test: %v", err)
	}
	store, err := openSSHKeyStore(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if _, err = store.read("authorized_keys"); err == nil || !strings.Contains(err.Error(), "keys_unsafe_file_permissions") {
		t.Fatalf("read of a world-writable key file = %v, want keys_unsafe_file_permissions", err)
	}
}

// Read-only access for other principals is what a profile's inherited ACEs
// often grant, and OpenSSH accepts it: only writing access matters.
func TestWindowsKeyStoreAcceptsReadOnlyInheritedAccess(t *testing.T) {
	dir := useTempKeyStore(t, "authorized_keys")
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte("existing\n"), 0600); err != nil {
		t.Fatal(err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.FILE_GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(users),
		},
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, dacl)
	if err != nil {
		t.Skipf("cannot add a read-only ACE: %v", err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Skipf("cannot add a read-only ACE: %v", err)
	}
	if _, err = manageSSHKey(t.TempDir(), "install", keyRequest()); err != nil {
		t.Fatalf("install with a read-only Users ACE = %v, want success", err)
	}
	if _, err = manageSSHKey(t.TempDir(), "list", sshKeyRequest{}); err != nil {
		t.Fatalf("list with a read-only Users ACE = %v", err)
	}
}

func TestWindowsKeyStoreLockRefusesASecondInstaller(t *testing.T) {
	useTempKeyStore(t, "authorized_keys")
	store, err := openSSHKeyStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	unlock, err := store.lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manageSSHKey(t.TempDir(), "install", keyRequest()); err == nil || !strings.Contains(err.Error(), "keys_busy") {
		t.Fatalf("a second installer = %v, want keys_busy", err)
	}
	unlock()
	if _, err = manageSSHKey(t.TempDir(), "install", keyRequest()); err != nil {
		t.Fatalf("installing after the lock was released: %v", err)
	}
}

func TestWindowsKeyStoreDetectsExternalChange(t *testing.T) {
	dir := useTempKeyStore(t, "authorized_keys")
	store, err := openSSHKeyStore(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	path := filepath.Join(dir, "authorized_keys")
	if err = os.WriteFile(path, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.read("authorized_keys")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("changed outside this installer\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = store.write("authorized_keys", []byte("replacement\n"), snapshot); err == nil {
		t.Fatal("overwrote external changes")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "changed outside this installer\n" {
		t.Fatal("lost external changes")
	}
}

// An administrator's key lives in ProgramData\ssh, whose ACL only an elevated
// process may change. Without elevation the installer says so instead of
// returning an access-denied error.
func TestWindowsKeyStoreNeedsAdminWhenNotElevated(t *testing.T) {
	if !windowsIsAdministrator() || windowsIsElevated() {
		t.Skip("only a non-elevated administrator runs into this rule")
	}
	_, err := openSSHKeyStore(t.TempDir(), true)
	if err == nil || !strings.Contains(err.Error(), "ssh_pair_needs_admin") {
		t.Fatalf("openSSHKeyStore as a non-elevated administrator = %v, want ssh_pair_needs_admin", err)
	}
}

func TestWindowsKeyJournalIsNotCreatedByListOrPreview(t *testing.T) {
	parent := profileLikeDir(t)
	missing := filepath.Join(parent, "missing-ssh")
	useKeyStoreAt(t, missing, "authorized_keys")
	// A missing .ssh is the empty listing, not an error, and nothing is created.
	listing, err := manageSSHKey(t.TempDir(), "list", sshKeyRequest{})
	if err != nil {
		t.Fatalf("list in a missing directory = %v, want the empty listing", err)
	}
	if records, ok := listing.(map[string]any)["keys"].([]sshKeyRecord); !ok || len(records) != 0 {
		t.Fatalf("list in a missing directory = %#v, want no keys", listing)
	}
	if _, err = os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("list created the key directory")
	}
	if _, err = manageSSHKey(t.TempDir(), "preview", keyRequest()); err != nil {
		t.Fatalf("preview in a missing directory = %v", err)
	}
	if _, err = os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preview created the key directory")
	}

	// An empty but existing directory behaves the same, and stays empty.
	empty := profileLikeDir(t)
	useKeyStoreAt(t, empty, "authorized_keys")
	if _, err = manageSSHKey(t.TempDir(), "list", sshKeyRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err = manageSSHKey(t.TempDir(), "preview", keyRequest()); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(empty); err != nil || len(entries) != 0 {
		t.Fatalf("list or preview created files: %v", err)
	}
}
