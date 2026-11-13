package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

// Set by the release build, monotonically increasing across stable releases.
// Dev binaries (zero) are never allowed to replace a numbered release.
var releaseSequence = "0"

func sequence() int64 { n, _ := strconv.ParseInt(releaseSequence, 10, 64); return n }

type updatePolicy struct {
	Enabled     bool            `json:"enabled"`
	MetadataURL string          `json:"metadataURL"`
	TargetsURL  string          `json:"targetsURL"`
	Root        json.RawMessage `json:"root"`
}
type updateState struct {
	State     string `json:"state"`
	Code      string `json:"code,omitempty"`
	Sequence  int64  `json:"sequence"`
	NextCheck int64  `json:"nextCheck"`
	Updated   int64  `json:"updated"`
}

// Read-only public progress: no policy, credentials, URLs or arbitrary errors.
func updateProgress(dir string) map[string]any {
	s := updateState{}
	if err := readPrivateJSON(filepath.Join(dir, "updates", "state.json"), &s); err != nil {
		return map[string]any{"state": "unknown"}
	}
	switch s.State {
	case "checking", "downloading", "verifying", "applying", "healthy", "failed":
	default:
		return map[string]any{"state": "unknown"}
	}
	stale := s.State != "healthy" && s.State != "failed" && (time.Now().Unix()-s.Updated > 300 || s.Updated > time.Now().Unix()+60)
	return map[string]any{"state": s.State, "sequence": s.Sequence, "updated": s.Updated, "stale": stale}
}

type releaseInfo struct {
	Sequence   int64  `json:"sequence"`
	APIVersion int    `json:"apiVersion"`
	Platform   string `json:"platform"`
}

func readPrivateJSON(path string, v any) error {
	if err := privatePath(path, false); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1024*1024+1))
	d.DisallowUnknownFields()
	if err = d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid_update_json")
	}
	return nil
}
func saveUpdateState(dir string, s updateState) error {
	s.Updated = time.Now().Unix()
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), filepath.Join(dir, "state.json"))
}

// No redirects, alternate hosts, infinite retries, or automatic decompression.
// TUF validates freshness, signatures, target hashes and lengths above this.
type updateFetcher struct {
	ctx     context.Context
	origins map[string]bool
	client  *http.Client
}

func (f updateFetcher) DownloadFile(raw string, max int64, _ time.Duration) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || !f.origins[u.Scheme+"://"+u.Host] || max <= 0 || max > 64*1024*1024 {
		return nil, errors.New("update_download_refused")
	}
	req, err := http.NewRequestWithContext(f.ctx, "GET", raw, nil)
	if err != nil {
		return nil, err
	}
	r, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, &metadata.ErrDownloadHTTP{StatusCode: r.StatusCode, URL: raw}
	}
	if r.ContentLength > max {
		return nil, errors.New("update_too_large")
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("update_too_large")
	}
	return b, nil
}

func verifiedUpdate(ctx context.Context, dir string, p updatePolicy, progress ...func(string) error) (string, releaseInfo, error) {
	return verifiedUpdateWithClient(ctx, dir, p, nil, progress...)
}

func verifiedUpdateWithClient(ctx context.Context, dir string, p updatePolicy, client *http.Client, progress ...func(string) error) (string, releaseInfo, error) {
	var info releaseInfo
	origins := map[string]bool{}
	for _, raw := range []string{p.MetadataURL, p.TargetsURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return "", info, errors.New("invalid_update_origin")
		}
		origins[u.Scheme+"://"+u.Host] = true
	}
	cfg, err := config.New(p.MetadataURL, p.Root)
	if err != nil {
		return "", info, err
	}
	cfg.LocalMetadataDir = filepath.Join(dir, "metadata")
	cfg.LocalTargetsDir = filepath.Join(dir, "targets")
	for _, path := range []string{cfg.LocalMetadataDir, cfg.LocalTargetsDir} {
		if err = prepareDir(path); err != nil {
			return "", info, err
		}
	}
	cfg.RemoteTargetsURL = p.TargetsURL
	cfg.MaxRootRotations = 8
	cfg.MaxDelegations = 8
	cfg.TargetsMaxLength = 1024 * 1024
	cfg.SnapshotMaxLength = 1024 * 1024
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, DisableCompression: true}
	defer tr.CloseIdleConnections()
	if client == nil {
		client = &http.Client{Transport: tr, Timeout: 180 * time.Second}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("update_redirect_refused") }
	cfg.Fetcher = updateFetcher{ctx, origins, &copyClient}
	u, err := updater.New(cfg)
	if err != nil {
		return "", info, err
	}
	if err = u.Refresh(); err != nil {
		return "", info, err
	}
	target, err := u.GetTargetInfo("agent/" + runtime.GOOS + "-" + runtime.GOARCH)
	if err != nil {
		return "", info, err
	}
	if target.Custom == nil || json.Unmarshal(*target.Custom, &info) != nil || info.Sequence <= 0 || info.APIVersion != 2 || info.Platform != runtime.GOOS+"-"+runtime.GOARCH || target.Length <= 0 || target.Length > 64*1024*1024 {
		return "", info, errors.New("incompatible_release")
	}
	if info.Sequence <= sequence() {
		return "", info, nil
	}
	// Only use the private TUF cache path selected by the library. Hash and length
	// are verified on both download and reuse; never trust an existing filename.
	path, _, err := u.FindCachedTarget(target, "")
	if err != nil {
		return "", info, err
	}
	if path == "" {
		if len(progress) > 0 {
			if err = progress[0]("downloading"); err != nil {
				return "", info, err
			}
		}
		path, _, err = u.DownloadTarget(target, "", "")
	}
	if err != nil {
		return "", info, err
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return "", info, errors.New("unsafe_update_target")
	}
	if err = os.Chmod(path, 0700); err != nil {
		return "", info, err
	}
	if err = privatePath(path, false); err != nil {
		return "", info, err
	}
	return path, info, nil
}

// Run from an SSH-launched helper, NOT inside the service's cgroup: stopping the
// service must not kill its updater. Independent OS lock coalesces many logins.
func checkUpdate(dir, creds string) error {
	ud := filepath.Join(dir, "updates")
	if err := prepareDir(ud); err != nil {
		return err
	}
	unlock, err := lockDir(ud)
	if err != nil {
		return errors.New("update_busy")
	}
	defer unlock()
	var policy updatePolicy
	if err = readPrivateJSON(filepath.Join(ud, "policy.json"), &policy); err != nil {
		return errors.New("update_not_configured")
	}
	if !policy.Enabled {
		return errors.New("automatic_updates_disabled")
	}
	s := updateState{}
	if err = readPrivateJSON(filepath.Join(ud, "state.json"), &s); err != nil && !os.IsNotExist(err) {
		return errors.New("invalid_update_state")
	}
	if s.NextCheck > time.Now().Unix() {
		return json.NewEncoder(os.Stdout).Encode(s)
	}
	// Persist cooldown before any network request. A killed SSH process cannot
	// cause each subsequent login to redownload/reapply the same failed release.
	s = updateState{State: "checking", NextCheck: time.Now().Add(time.Hour).Unix(), Sequence: s.Sequence}
	if err = saveUpdateState(ud, s); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	path, info, err := verifiedUpdate(ctx, ud, policy, func(phase string) error {
		s.State = phase
		return saveUpdateState(ud, s)
	})
	if err == nil && info.Sequence < s.Sequence {
		err = errors.New("release_downgrade_refused")
	}
	if err == nil && path != "" {
		s.State = "verifying"
		if err = saveUpdateState(ud, s); err != nil {
			return err
		}
		// Verify signed release metadata agrees with the actual executable before
		// allowing it to take over a service. The executable itself is TUF verified.
		var b []byte
		b, err = exec.CommandContext(ctx, path, "build-info").Output()
		var actual releaseInfo
		if err == nil && (json.Unmarshal(b, &actual) != nil || actual != info) {
			err = errors.New("release_identity_mismatch")
		}
		if err == nil {
			s.State = "applying"
			s.Sequence = info.Sequence
			if err = saveUpdateState(ud, s); err == nil {
				cmd := exec.CommandContext(ctx, path, "--state-dir", dir, "--credentials-dir", creds, "apply-update")
				err = cmd.Run()
				if err == nil {
					err = exec.CommandContext(ctx, path, "--state-dir", dir, "--credentials-dir", creds, "refresh-integrations").Run()
				}
			}
		}
	}
	if err != nil {
		s.State = "failed"
		s.Code = "update_failed_previous_service_retained_or_recovery_required"
	} else {
		s.State = "healthy"
		s.Code = ""
		s.Sequence = info.Sequence
		s.NextCheck = time.Now().Add(6 * time.Hour).Unix()
	}
	if e := saveUpdateState(ud, s); e != nil {
		return e
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(s)
}

func updateBuildInfo() error {
	return json.NewEncoder(os.Stdout).Encode(releaseInfo{sequence(), 2, runtime.GOOS + "-" + runtime.GOARCH})
}

// Bootstrap is an explicit local/SSH action: root bytes must come from a trusted
// App/release, never downloaded from the same server they are meant to verify.
func configureUpdates(dir string, input io.Reader) error {
	var p updatePolicy
	d := json.NewDecoder(io.LimitReader(input, 1024*1024+1))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid_update_policy")
	}
	for _, raw := range []string{p.MetadataURL, p.TargetsURL} {
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("invalid_update_origin")
		}
	}
	root, err := metadata.Root().FromBytes(p.Root)
	if err != nil {
		return errors.New("invalid_update_root")
	}
	if err = root.VerifyDelegate("root", root); err != nil {
		return errors.New("invalid_update_root")
	}
	ud := filepath.Join(dir, "updates")
	if err = prepareDir(ud); err != nil {
		return err
	}
	unlock, err := lockDir(ud)
	if err != nil {
		return errors.New("update_busy")
	}
	defer unlock()
	path := filepath.Join(ud, "policy.json")
	if _, err = os.Lstat(path); err == nil {
		if err = privatePath(path, false); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(ud, ".policy-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]bool{"configured": true})
}

func startUpdate(dir, creds string) error {
	if _, err := os.Lstat(filepath.Join(dir, "updates-disabled")); err == nil || !os.IsNotExist(err) {
		return nil
	}
	// Missing opt-in is a no-op, including on hosts whose daemon was uninstalled.
	var p updatePolicy
	if err := readPrivateJSON(filepath.Join(dir, "updates", "policy.json"), &p); err != nil || !p.Enabled {
		return nil
	}
	// Never resurrect a removed service as a side effect of opening a terminal.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := dialLocal(ctx, dir)
	if err != nil {
		return nil
	}
	c.Close()
	exe, err := executablePath()
	if err != nil {
		return err
	}
	return detachUpdater(exe, dir, creds)
}
