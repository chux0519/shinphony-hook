package main

// The `keys` CLI contract shared by macOS, Linux and Windows: request parsing,
// the key journal's state machine and the rules for the authorized_keys lines.
//
// Only storage is platform-specific: Unix keeps an open descriptor on ~/.ssh
// with ownership and mode checks, Windows picks %USERPROFILE%\.ssh or
// C:\ProgramData\ssh depending on whether the account is an administrator and
// checks ACLs instead. Both expose openSSHKeyStore; this file never touches the
// file system itself.

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// sshKeyFileLimit bounds every file this package writes or reads, so a
// corrupted or hostile authorized_keys cannot exhaust memory.
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

// sshKeySnapshot is a file's content plus its identity on this platform, so a
// concurrent external edit is detected instead of overwritten.
type sshKeySnapshot struct {
	data []byte
	stat *sshKeyStat
}

// sshKeyStore is the platform storage for the journal and the keys file.
// read and write take a bare file name inside the account's SSH directory.
type sshKeyStore interface {
	read(name string) (sshKeySnapshot, error)
	write(name string, data []byte, expected sshKeySnapshot) error
	// lock takes the exclusive installer lock without waiting.
	lock() (func(), error)
	close()
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
	if err := keysPrivilegeCheck(); err != nil {
		return err
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

// sshKeyExpectedLine is the managed line for one key; the comment carries the
// id so revoke can remove exactly this line and nothing else.
func sshKeyExpectedLine(record sshKeyRecord, id string) string {
	return record.PublicKey + " shinphony:" + id
}

// countSSHKeyLines counts the managed line and any line that already carries
// the same public key under another comment.
func countSSHKeyLines(data []byte, record sshKeyRecord, id string) (owned, other int) {
	expected := sshKeyExpectedLine(record, id)
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		value := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if value == expected {
			owned++
			continue
		}
		fields := strings.Fields(value)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i]+" "+fields[i+1] == record.PublicKey {
				other++
				break
			}
		}
	}
	return owned, other
}

func manageSSHKey(home, operation string, request sshKeyRequest) (any, error) {
	result, err := manageSSHKeyIn(home, operation, request, openSSHKeyStore)
	// A key written where this account's keys used to go (Windows: the shared
	// administrator file before sshd_config was consulted) is still revoked
	// there.
	if operation == "revoke" && err != nil && (err.Error() == "keys_not_managed" || errors.Is(err, os.ErrNotExist)) {
		fallback, openErr := openFallbackSSHKeyStore(home)
		if openErr == nil && fallback != nil {
			fallback.close()
			return manageSSHKeyIn(home, operation, request, func(string, bool) (sshKeyStore, error) {
				return openFallbackSSHKeyStore(home)
			})
		}
		if openErr != nil && !errors.Is(openErr, os.ErrNotExist) {
			return nil, openErr
		}
	}
	return result, err
}

func manageSSHKeyIn(home, operation string, request sshKeyRequest, open func(string, bool) (sshKeyStore, error)) (any, error) {
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
	store, err := open(home, operation == "install")
	if errors.Is(err, os.ErrNotExist) && operation == "list" {
		return map[string]any{"schema": 1, "keys": []sshKeyRecord{}}, nil
	}
	if err != nil {
		return nil, err
	}
	defer store.close()
	if operation == "list" {
		meta, err := store.read(".shinphony-keys.json")
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
	unlock, err := store.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	meta, err := store.read(".shinphony-keys.json")
	if err != nil {
		return nil, err
	}
	journal := sshKeyJournal{Schema: 1, Keys: map[string]sshKeyRecord{}}
	if meta.stat != nil {
		if json.Unmarshal(meta.data, &journal) != nil || journal.Schema != 1 || journal.Keys == nil {
			return nil, errors.New("keys_journal_invalid")
		}
	}
	keys, err := store.read("authorized_keys")
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
	ownedCount, otherCount := countSSHKeyLines(keys.data, record, request.ID)
	if otherCount > 0 || ownedCount > 1 || (!known && ownedCount > 0) {
		return nil, errors.New("keys_already_authorized_elsewhere")
	}
	writeJournal := func() error {
		journal.Keys[request.ID] = record
		data, err := json.Marshal(journal)
		if err != nil {
			return err
		}
		if err = store.write(".shinphony-keys.json", data, meta); err != nil {
			return err
		}
		meta, err = store.read(".shinphony-keys.json")
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
			data = append(data, []byte(sshKeyExpectedLine(record, request.ID)+"\n")...)
			if err = store.write("authorized_keys", data, keys); err != nil {
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
			expected := sshKeyExpectedLine(record, request.ID)
			data := []byte{}
			for _, line := range bytes.SplitAfter(keys.data, []byte("\n")) {
				if strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r") != expected {
					data = append(data, line...)
				}
			}
			if err = store.write("authorized_keys", data, keys); err != nil {
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
	store, err := openSSHKeyStore(home, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		defer store.close()
		if _, err := store.read("authorized_keys"); err != nil {
			return nil, err
		}
		if _, err := store.read(".shinphony-keys.json"); err != nil {
			return nil, err
		}
	}
	return map[string]any{"schema": 1, "id": request.ID, "fingerprint": fingerprint,
		"addition": sshKeyExpectedLine(sshKeyRecord{PublicKey: request.PublicKey}, request.ID)}, nil
}
