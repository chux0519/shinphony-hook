package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// MetadataSummary is the verified view of one published sequence, used by
// tool/verify_reproducible.sh to compare locally built binaries.
type MetadataSummary struct {
	Sequence int64                 `json:"sequence"`
	Expires  string                `json:"expires"`
	Targets  map[string]TargetInfo `json:"targets"`
}

type TargetInfo struct {
	SHA256 string `json:"sha256"`
	Length int64  `json:"length"`
}

const (
	defaultMetadataBase = "https://downloads.potafree.net/agent/stable/metadata"
	maxMetadataBytes    = 256 * 1024
)

var metadataRoles = []string{"timestamp", "snapshot", "targets"}

// VerifyMetadataURL fetches the published TUF metadata from baseURL and
// verifies it against the pinned root (deploy/root.json). It returns only the
// hashes that were signed; unverified metadata is never reported as current.
func VerifyMetadataURL(baseURL, pinnedRootFile string, now time.Time) (MetadataSummary, error) {
	var summary MetadataSummary
	rootBytes, err := os.ReadFile(pinnedRootFile)
	if err != nil {
		return summary, fmt.Errorf("pinned root: %w", err)
	}
	client := &http.Client{Timeout: 20 * time.Second}
	files := map[string][]byte{"root": rootBytes}
	for _, role := range metadataRoles {
		body, err := fetchMetadata(client, baseURL, role)
		if err != nil {
			return summary, err
		}
		files[role] = body
	}
	return verifyMetadataSet(files["root"], files["timestamp"], files["snapshot"], files["targets"], now)
}

func fetchMetadata(client *http.Client, baseURL, role string) ([]byte, error) {
	url := baseURL + "/" + role + ".json"
	res, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", role, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", role, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxMetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", role, err)
	}
	if len(body) == 0 || len(body) > maxMetadataBytes {
		return nil, fmt.Errorf("read %s: size %d", role, len(body))
	}
	return body, nil
}

// verifyMetadataSet checks the root's self-signature and the full
// timestamp -> snapshot -> targets chain: signatures by the pinned keys,
// expiry, declared hashes and lengths, and matching versions.
func verifyMetadataSet(rootBytes, timestampBytes, snapshotBytes, targetsBytes []byte, now time.Time) (MetadataSummary, error) {
	var summary MetadataSummary
	root, err := metadata.Root().FromBytes(rootBytes)
	if err != nil {
		return summary, fmt.Errorf("root: %w", err)
	}
	if err := root.VerifyDelegate("root", root); err != nil {
		return summary, fmt.Errorf("root: %w", err)
	}
	if expired(root.Signed.Expires, now) {
		return summary, fmt.Errorf("root: expired %s", root.Signed.Expires.Format(time.RFC3339))
	}

	timestamp, err := metadata.Timestamp().FromBytes(timestampBytes)
	if err != nil {
		return summary, fmt.Errorf("timestamp: %w", err)
	}
	if err := root.VerifyDelegate("timestamp", timestamp); err != nil {
		return summary, fmt.Errorf("timestamp: %w", err)
	}
	if expired(timestamp.Signed.Expires, now) {
		return summary, fmt.Errorf("timestamp: expired %s", timestamp.Signed.Expires.Format(time.RFC3339))
	}
	snapshotMeta, ok := timestamp.Signed.Meta["snapshot.json"]
	if !ok {
		return summary, fmt.Errorf("timestamp: no snapshot.json entry")
	}
	if err := matchMeta(snapshotBytes, snapshotMeta, "snapshot"); err != nil {
		return summary, err
	}

	snapshot, err := metadata.Snapshot().FromBytes(snapshotBytes)
	if err != nil {
		return summary, fmt.Errorf("snapshot: %w", err)
	}
	if err := root.VerifyDelegate("snapshot", snapshot); err != nil {
		return summary, fmt.Errorf("snapshot: %w", err)
	}
	if expired(snapshot.Signed.Expires, now) {
		return summary, fmt.Errorf("snapshot: expired %s", snapshot.Signed.Expires.Format(time.RFC3339))
	}
	if snapshot.Signed.Version != snapshotMeta.Version {
		return summary, fmt.Errorf("snapshot: version %d, timestamp declares %d", snapshot.Signed.Version, snapshotMeta.Version)
	}
	targetsMeta, ok := snapshot.Signed.Meta["targets.json"]
	if !ok {
		// Consistent snapshots may publish only the versioned name.
		targetsMeta, ok = snapshot.Signed.Meta[fmt.Sprintf("%d.targets.json", snapshotMeta.Version)]
	}
	if !ok {
		return summary, fmt.Errorf("snapshot: no targets.json entry")
	}
	if err := matchMeta(targetsBytes, targetsMeta, "targets"); err != nil {
		return summary, err
	}

	targets, err := metadata.Targets().FromBytes(targetsBytes)
	if err != nil {
		return summary, fmt.Errorf("targets: %w", err)
	}
	if err := root.VerifyDelegate("targets", targets); err != nil {
		return summary, fmt.Errorf("targets: %w", err)
	}
	if expired(targets.Signed.Expires, now) {
		return summary, fmt.Errorf("targets: expired %s", targets.Signed.Expires.Format(time.RFC3339))
	}
	if targets.Signed.Version != targetsMeta.Version {
		return summary, fmt.Errorf("targets: version %d, snapshot declares %d", targets.Signed.Version, targetsMeta.Version)
	}

	summary.Targets = map[string]TargetInfo{}
	for _, platform := range platforms {
		name := "agent/" + platform
		target, ok := targets.Signed.Targets[name]
		if !ok {
			return MetadataSummary{}, fmt.Errorf("targets: missing %s", name)
		}
		hash := hex.EncodeToString(target.Hashes["sha256"])
		if !sha256Hex.MatchString(hash) || target.Length <= 0 || target.Length > 64<<20 {
			return MetadataSummary{}, fmt.Errorf("targets: invalid entry for %s", platform)
		}
		if !validCustom(target.Custom, platform) {
			return MetadataSummary{}, fmt.Errorf("targets: invalid custom fields for %s", platform)
		}
		summary.Targets[platform] = TargetInfo{SHA256: hash, Length: target.Length}
	}
	summary.Sequence = targets.Signed.Version
	summary.Expires = targets.Signed.Expires.UTC().Format(time.RFC3339)
	return summary, nil
}

func expired(at, now time.Time) bool {
	return at.IsZero() || !at.After(now)
}

func matchMeta(body []byte, meta *metadata.MetaFiles, role string) error {
	if meta == nil {
		return fmt.Errorf("%s: empty metadata entry", role)
	}
	if int64(len(body)) != meta.Length {
		return fmt.Errorf("%s: length %d, metadata declares %d", role, len(body), meta.Length)
	}
	want := hex.EncodeToString(meta.Hashes["sha256"])
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != want {
		return fmt.Errorf("%s: sha256 does not match the signed metadata", role)
	}
	return nil
}

func validCustom(raw *json.RawMessage, platform string) bool {
	if raw == nil {
		return false
	}
	var custom struct {
		Platform   string `json:"platform"`
		APIVersion int    `json:"apiVersion"`
	}
	if err := json.Unmarshal(*raw, &custom); err != nil {
		return false
	}
	return custom.Platform == platform && custom.APIVersion == 2
}
