package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestPublishedRelease(t *testing.T) {
	path := os.Getenv("SHINPHONY_TEST_RELEASE_POLICY")
	if path == "" {
		t.Skip("opt-in public signed release verification")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var p updatePolicy
	if err = json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	file, info, err := verifiedUpdate(ctx, privateTemp(t), p)
	if err != nil || file == "" || info.Sequence < 2026102301 {
		t.Fatal(file, info, err)
	}
	t.Logf("verified public target %s sequence %d", info.Platform, info.Sequence)
}

func signedFixture(t *testing.T, corrupt, expired bool) (updatePolicy, *http.Client) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadSigner(key, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := metadata.KeyFromPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if expired {
		exp = time.Now().Add(-time.Hour)
	}
	root := metadata.Root(time.Now().Add(time.Hour))
	root.Signed.ConsistentSnapshot = false
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if err = root.Signed.AddKey(pub, role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = root.Sign(signer); err != nil {
		t.Fatal(err)
	}
	raw, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	platform := runtime.GOOS + "-" + runtime.GOARCH
	body := []byte("verified binary fixture")
	target, err := metadata.TargetFile().FromBytes("agent/"+platform, body, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	custom, _ := json.Marshal(releaseInfo{1, 2, platform})
	r := json.RawMessage(custom)
	target.Custom = &r
	targets := metadata.Targets(exp)
	targets.Signed.Targets["agent/"+platform] = target
	snapshot := metadata.Snapshot(exp)
	snapshot.Signed.Meta["targets.json"] = metadata.MetaFile(1)
	timestamp := metadata.Timestamp(exp)
	timestamp.Signed.Meta["snapshot.json"] = metadata.MetaFile(1)
	if _, err = targets.Sign(signer); err != nil {
		t.Fatal(err)
	}
	if _, err = snapshot.Sign(signer); err != nil {
		t.Fatal(err)
	}
	if _, err = timestamp.Sign(signer); err != nil {
		t.Fatal(err)
	}
	tb, _ := targets.ToBytes(false)
	sb, _ := snapshot.ToBytes(false)
	ts, _ := timestamp.ToBytes(false)
	if corrupt {
		body = []byte("modified binary fixture")
	}
	files := map[string][]byte{"/metadata/timestamp.json": ts, "/metadata/snapshot.json": sb, "/metadata/targets.json": tb, "/targets/agent/" + platform: body}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return updatePolicy{true, srv.URL + "/metadata/", srv.URL + "/targets/", raw}, srv.Client()
}
func TestVerifiedUpdateTUF(t *testing.T) {
	for _, tc := range []struct {
		name             string
		corrupt, expired bool
	}{{"valid", false, false}, {"tampered", true, false}, {"expired", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			p, c := signedFixture(t, tc.corrupt, tc.expired)
			dir := privateTemp(t)
			path, info, err := verifiedUpdateWithClient(context.Background(), dir, p, c)
			if tc.corrupt || tc.expired {
				if err == nil {
					t.Fatal("unsafe update accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(path)
			if err != nil || string(b) != "verified binary fixture" || info.Sequence != 1 {
				t.Fatal(path, info, err)
			}
			// The immutable target must still be validated on cache reuse.
			if err = os.WriteFile(path, []byte("tampered cache"), 0700); err != nil {
				t.Fatal(err)
			}
			path, _, err = verifiedUpdateWithClient(context.Background(), dir, p, c)
			if err != nil {
				t.Fatal(err)
			}
			b, _ = os.ReadFile(path)
			if string(b) != "verified binary fixture" {
				t.Fatal("trusted tampered cache")
			}
		})
	}
}
func TestUpdateFetcherBounds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", 20))) }))
	defer srv.Close()
	f := updateFetcher{context.Background(), map[string]bool{srv.URL: true}, srv.Client()}
	if _, err := f.DownloadFile(srv.URL, 10, 0); err == nil {
		t.Fatal("oversized accepted")
	}
	if _, err := f.DownloadFile("http://untrusted.invalid", 10, 0); err == nil {
		t.Fatal("origin accepted")
	}
}
func TestUpdateCooldownAndDisabled(t *testing.T) {
	dir := privateTemp(t)
	ud := filepath.Join(dir, "updates")
	if err := prepareDir(ud); err != nil {
		t.Fatal(err)
	}
	if err := checkUpdate(dir, dir, 0); err == nil {
		t.Fatal("missing trust root accepted")
	}
	p := updatePolicy{}
	b, _ := json.Marshal(p)
	os.WriteFile(filepath.Join(ud, "policy.json"), b, 0600)
	if err := checkUpdate(dir, dir, 0); err == nil || err.Error() != "automatic_updates_disabled" {
		t.Fatal(err)
	}
	p.Enabled = true
	b, _ = json.Marshal(p)
	os.WriteFile(filepath.Join(ud, "policy.json"), b, 0600)
	if err := saveUpdateState(ud, updateState{State: "checking", NextCheck: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if err := checkUpdate(dir, dir, 0); err != nil {
			t.Fatal("cooldown should avoid all network", err)
		}
	}
}

func TestUninstallTombstoneBlocksAutomaticApply(t *testing.T) {
	dir := privateTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "updates-disabled"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureServiceMode(dir, dir, true); err == nil || err.Error() != "automatic_updates_disabled" {
		t.Fatal(err)
	}
	if err := startUpdate(dir, dir); err != nil {
		t.Fatal(err)
	}
}

// `check-update --min-sequence N` is the App's "your Hook is old" lever: below N
// it must not wait for the hourly cooldown, at or above N it behaves as today.
func TestUpdateDueHonoursMinSequence(t *testing.T) {
	now := time.Unix(1794756000, 0).UTC()
	soon := updateState{State: "checking", NextCheck: now.Unix() + 3600}
	for _, tc := range []struct {
		name string
		s    updateState
		min  int64
		want bool
	}{
		{"no-cooldown", updateState{}, 0, true},
		{"cooldown", soon, 0, false},
		{"cooldown-min-above-installed", soon, sequence() + 1, true},
		{"cooldown-min-equal-installed", soon, sequence(), false},
		{"cooldown-min-below-installed", soon, -1, false},
	} {
		if got := updateDue(tc.s, tc.min, now); got != tc.want {
			t.Fatalf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The flag is new: the position the App uses (`check-update --min-sequence N`)
// must parse, and so must the flag-before-command form the Go flag package
// accepts for every other option. Anything else is a usage error, never a
// silently ignored typo on a command that changes the installed binary.
func TestCheckUpdateArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		pre  int64
		want int64
		err  bool
	}{
		{"plain", nil, 0, 0, false},
		{"space", []string{"--min-sequence", "2026111601"}, 0, 2026111601, false},
		{"equals", []string{"--min-sequence=2026111601"}, 0, 2026111601, false},
		{"flag-given-twice", []string{"--min-sequence", "5"}, 7, 5, false},
		{"empty", []string{"--min-sequence"}, 0, 0, true},
		{"garbage", []string{"--min-sequence", "next"}, 0, 0, true},
		{"negative", []string{"--min-sequence", "-3"}, 0, 0, true},
		{"unknown-flag", []string{"--force"}, 0, 0, true},
		{"stray-word", []string{"now"}, 0, 0, true},
	} {
		got, err := checkUpdateMinSequence(tc.args, tc.pre)
		if (err != nil) != tc.err {
			t.Fatalf("%s: err %v, want error %v", tc.name, err, tc.err)
		}
		if !tc.err && got != tc.want {
			t.Fatalf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}
