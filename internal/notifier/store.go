package notifier

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var secret = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type credential struct {
	Schema int    `json:"schema"`
	Lane   string `json:"lane"`
	Host   string `json:"hostId"`
	Token  string `json:"hostToken"`
}

func (c credential) valid() bool {
	_, err := lanePrefix(c.Lane)
	return c.Schema == 1 && err == nil && identifier.MatchString(c.Host) && secret.MatchString(c.Token)
}

type store struct{ dir string }

func defaultStore() (store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return store{}, errConfig
	}
	// Separate from Python config; never silently replaces an existing destination.
	return store{filepath.Join(home, ".shinphony-notify")}, nil
}
func (s store) initialize() error {
	// Only the final owned directory may be created. Do not chmod existing paths.
	if err := checkParents(filepath.Dir(s.dir)); err != nil {
		return err
	}
	err := makePrivateDir(s.dir)
	if err != nil && !os.IsExist(err) {
		return errUnsafe
	}
	return checkPrivate(s.dir, true)
}
func (s store) path(profile string) (string, error) {
	if !identifier.MatchString(profile) {
		return "", errConfig
	}
	return filepath.Join(s.dir, profile+".json"), nil
}
func readPrivate(path string) ([]byte, error) {
	if err := checkPrivate(path, false); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errConfig
	}
	defer f.Close()
	// Verify the opened file too, rejecting replacement between check and open.
	a, err := f.Stat()
	if err != nil {
		return nil, errUnsafe
	}
	b, err := os.Lstat(path)
	if err != nil || !os.SameFile(a, b) {
		return nil, errUnsafe
	}
	raw, err := io.ReadAll(io.LimitReader(f, 2097153))
	if err != nil || len(raw) > 2097152 {
		return nil, errConfig
	}
	return raw, nil
}
func (s store) load(profile string) (credential, error) {
	var c credential
	if err := checkPrivate(s.dir, true); err != nil {
		return c, err
	}
	p, err := s.path(profile)
	if err != nil {
		return c, err
	}
	raw, err := readPrivate(p)
	if err != nil {
		return c, err
	}
	if len(raw) > 8192 || json.Unmarshal(raw, &c) != nil || !c.valid() {
		return credential{}, errConfig
	}
	return c, nil
}
func (s store) lock(profile string) (func(), error) {
	if !identifier.MatchString(profile) {
		return nil, errConfig
	}
	p := filepath.Join(s.dir, profile+".lock")
	f, err := createPrivate(p)
	if err != nil {
		return nil, errors.New("busy_or_interrupted_install")
	}
	f.Close()
	return func() { os.Remove(p) }, nil
}
func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("random_unavailable")
	}
	return hex.EncodeToString(b[:])
}

// Commit via hard link: atomic and never overwrites an existing credential.
// A crash can leave a private temporary file, but never a partially written destination.
func (s store) saveNew(profile string, c credential) error {
	if !c.valid() {
		return errConfig
	}
	p, err := s.path(profile)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, ".stage-"+randomID())
	f, err := createPrivate(tmp)
	if err != nil {
		return errUnsafe
	}
	defer os.Remove(tmp)
	raw, _ := json.Marshal(c)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("credential_write_failed")
	}
	if err = os.Link(tmp, p); err != nil {
		return errors.New("credential_commit_failed")
	}
	return nil
}

// Preflight and journal happen BEFORE consuming a one-use pairing code.
// Response loss keeps a marker; no retry/rotation of existing host credentials.
func (s store) pair(profile, lane, host, code string, r relay) error {
	if !identifier.MatchString(profile) || !identifier.MatchString(host) || !secret.MatchString(code) {
		return errConfig
	}
	if _, err := lanePrefix(lane); err != nil {
		return err
	}
	if err := s.initialize(); err != nil {
		return err
	}
	unlock, err := s.lock(profile)
	if err != nil {
		return err
	}
	defer unlock()
	p, _ := s.path(profile)
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		return errors.New("profile_already_exists")
	}
	marker := filepath.Join(s.dir, profile+".pending")
	f, err := createPrivate(marker)
	if err != nil {
		return errors.New("pairing_needs_reconciliation")
	}
	// No code/token in marker. Explicitly keep it on ambiguous network failure.
	if err = f.Sync(); err != nil {
		f.Close()
		return errors.New("journal_write_failed")
	}
	f.Close()
	var reply struct {
		Token string `json:"hostToken"`
		Host  string `json:"hostId"`
	}
	ctx, cancel := networkContext()
	defer cancel()
	if err = r.post(ctx, lane, "/v1/pair/exchange", "", map[string]string{"pairingCode": code}, &reply); err != nil {
		return errors.New("pairing_needs_reconciliation")
	}
	c := credential{1, lane, reply.Host, reply.Token}
	if !c.valid() || reply.Host != host {
		return errors.New("pairing_needs_reconciliation")
	}
	if err = s.saveNew(profile, c); err != nil {
		return errors.New("pairing_needs_reconciliation")
	}
	if err = os.Remove(marker); err != nil {
		return errors.New("paired_cleanup_pending")
	}
	return nil
}
