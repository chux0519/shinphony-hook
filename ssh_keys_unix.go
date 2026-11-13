//go:build darwin || linux

package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const sshKeyFileLimit = 1024 * 1024

type sshKeyRecord struct {
	ID          string `json:"id"`
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"`
}
type sshKeyJournal struct {
	Schema int                     `json:"schema"`
	Keys   map[string]sshKeyRecord `json:"keys"`
}
type sshKeyRequest struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
}
type sshKeySnapshot struct {
	data []byte
	stat *unix.Stat_t
}

var sshKeyID = regexp.MustCompile(`^se-p256:[a-fA-F0-9-]{36}$`)

func keysCLI(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 2 && args[0] == "revoke" && sshKeyID.MatchString(args[1]) {
		input = strings.NewReader(`{"id":"` + args[1] + `"}`)
		args = args[:1]
	}
	if len(args) != 1 || (args[0] != "install" && args[0] != "list" && args[0] != "revoke" && args[0] != "preview") {
		return errors.New("usage: keys list | revoke <key-id> | preview|install|revoke (request JSON on stdin)")
	}
	if os.Geteuid() == 0 {
		return errors.New("keys_root_not_supported")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("keys_home_unavailable")
	}
	var request sshKeyRequest
	if args[0] != "list" {
		raw, err := io.ReadAll(io.LimitReader(input, 8193))
		if err != nil || len(raw) > 8192 {
			return errors.New("keys_invalid_input")
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || !sshKeyID.MatchString(request.ID) {
			return errors.New("keys_invalid_input")
		}
	}
	result, err := manageSSHKey(home, args[0], request)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}

func validateP256PublicKey(value string) (string, error) {
	fields := strings.Split(value, " ")
	if len(value) > 2048 || len(fields) != 2 || fields[0] != "ecdsa-sha2-nistp256" {
		return "", errors.New("keys_invalid_public_key")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(fields[1])
	if err != nil {
		return "", errors.New("keys_invalid_public_key")
	}
	remaining := raw
	field := func() ([]byte, bool) {
		if len(remaining) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(remaining)
		remaining = remaining[4:]
		if uint64(n) > uint64(len(remaining)) {
			return nil, false
		}
		v := remaining[:n]
		remaining = remaining[n:]
		return v, true
	}
	algorithm, ok := field()
	if !ok || string(algorithm) != "ecdsa-sha2-nistp256" {
		return "", errors.New("keys_invalid_public_key")
	}
	curve, ok := field()
	if !ok || string(curve) != "nistp256" {
		return "", errors.New("keys_invalid_public_key")
	}
	point, ok := field()
	if !ok || len(remaining) != 0 {
		return "", errors.New("keys_invalid_public_key")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), point)
	if x == nil || y == nil {
		return "", errors.New("keys_invalid_public_key")
	}
	hash := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:]), nil
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

func manageSSHKey(home, operation string, request sshKeyRequest) (any, error) {
	if operation == "preview" {
		return previewSSHKey(home, request)
	}
	if operation != "list" && !sshKeyID.MatchString(request.ID) {
		return nil, errors.New("keys_invalid_id")
	}
	fingerprint := ""
	if operation == "install" {
		var err error
		fingerprint, err = validateP256PublicKey(request.PublicKey)
		if err != nil {
			return nil, err
		}
	}
	dir, err := sshKeyDirectory(home, operation == "install")
	if errors.Is(err, os.ErrNotExist) && operation == "list" {
		return map[string]any{"schema": 1, "keys": []sshKeyRecord{}}, nil
	}
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	if operation == "list" {
		meta, err := sshKeyRead(dir, ".shinphony-keys.json")
		if err != nil {
			return nil, err
		}
		journal := sshKeyJournal{Schema: 1, Keys: map[string]sshKeyRecord{}}
		if meta.stat != nil && (json.Unmarshal(meta.data, &journal) != nil || journal.Schema != 1 || journal.Keys == nil) {
			return nil, errors.New("keys_journal_invalid")
		}
		records := []sshKeyRecord{}
		for _, record := range journal.Keys {
			records = append(records, record)
		}
		sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
		return map[string]any{"schema": 1, "keys": records}, nil
	}
	lock, err := unix.Openat(dir, ".shinphony-keys.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
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
	defer unix.Flock(lock, unix.LOCK_UN)
	meta, err := sshKeyRead(dir, ".shinphony-keys.json")
	if err != nil {
		return nil, err
	}
	journal := sshKeyJournal{Schema: 1, Keys: map[string]sshKeyRecord{}}
	if meta.stat != nil {
		if json.Unmarshal(meta.data, &journal) != nil || journal.Schema != 1 || journal.Keys == nil {
			return nil, errors.New("keys_journal_invalid")
		}
	}
	keys, err := sshKeyRead(dir, "authorized_keys")
	if err != nil {
		return nil, err
	}
	record, known := journal.Keys[request.ID]
	if known && (record.ID != request.ID || record.PublicKey == "" || (operation == "install" && record.PublicKey != request.PublicKey)) {
		return nil, errors.New("keys_record_mismatch")
	}
	if operation == "revoke" && !known {
		return nil, errors.New("keys_not_managed")
	}
	if !known {
		record = sshKeyRecord{ID: request.ID, PublicKey: request.PublicKey, Fingerprint: fingerprint}
	}
	expected := record.PublicKey + " shinphony:" + request.ID
	ownedCount, otherCount := 0, 0
	lines := bytes.SplitAfter(keys.data, []byte("\n"))
	for _, line := range lines {
		value := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if value == expected {
			ownedCount++
			continue
		}
		fields := strings.Fields(value)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i]+" "+fields[i+1] == record.PublicKey {
				otherCount++
				break
			}
		}
	}
	if otherCount > 0 || ownedCount > 1 || (!known && ownedCount > 0) {
		return nil, errors.New("keys_already_authorized_elsewhere")
	}
	writeJournal := func() error {
		journal.Keys[request.ID] = record
		data, err := json.Marshal(journal)
		if err != nil {
			return err
		}
		if err = sshKeyWrite(dir, ".shinphony-keys.json", data, meta); err != nil {
			return err
		}
		meta, err = sshKeyRead(dir, ".shinphony-keys.json")
		return err
	}
	if operation == "install" {
		if record.State == "installed" && ownedCount == 0 {
			return nil, errors.New("keys_managed_line_changed")
		}
		record.State = "installing"
		if err = writeJournal(); err != nil {
			return nil, err
		}
		if ownedCount == 0 {
			data := append([]byte{}, keys.data...)
			if len(data) > 0 && data[len(data)-1] != '\n' {
				data = append(data, '\n')
			}
			data = append(data, []byte(expected+"\n")...)
			if err = sshKeyWrite(dir, "authorized_keys", data, keys); err != nil {
				return nil, err
			}
		}
		record.State = "installed"
	} else {
		if record.State == "installed" && ownedCount == 0 {
			return nil, errors.New("keys_managed_line_changed")
		}
		record.State = "revoking"
		if err = writeJournal(); err != nil {
			return nil, err
		}
		if ownedCount == 1 {
			data := []byte{}
			for _, line := range lines {
				if strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r") != expected {
					data = append(data, line...)
				}
			}
			if err = sshKeyWrite(dir, "authorized_keys", data, keys); err != nil {
				return nil, err
			}
		}
		record.State = "revoked"
	}
	if err = writeJournal(); err != nil {
		return nil, err
	}
	return map[string]any{"schema": 1, "id": request.ID, "state": record.State, "fingerprint": record.Fingerprint}, nil
}

func previewSSHKey(home string, request sshKeyRequest) (any, error) {
	if !sshKeyID.MatchString(request.ID) {
		return nil, errors.New("keys_invalid_id")
	}
	fingerprint, err := validateP256PublicKey(request.PublicKey)
	if err != nil {
		return nil, err
	}
	dir, err := sshKeyDirectory(home, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if dir >= 0 {
		defer unix.Close(dir)
		if _, err := sshKeyRead(dir, "authorized_keys"); err != nil {
			return nil, err
		}
		if _, err := sshKeyRead(dir, ".shinphony-keys.json"); err != nil {
			return nil, err
		}
	}
	return map[string]any{"schema": 1, "id": request.ID, "fingerprint": fingerprint,
		"addition": request.PublicKey + " shinphony:" + request.ID}, nil
}
