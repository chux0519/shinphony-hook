// Offline release publisher. Private keys never enter the public output tree.
package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func write(path string, b []byte, mode os.FileMode) {
	must(os.MkdirAll(filepath.Dir(path), 0755))
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	must(e)
	_, e = f.Write(b)
	must(e)
	must(f.Sync())
	must(f.Close())
}
func key(dir, name string) ed25519.PrivateKey {
	path := filepath.Join(dir, name+".key")
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		write(path, k, 0600)
		return k
	}
	must(e)
	st, e := os.Stat(path)
	must(e)
	if st.Mode().Perm()&0077 != 0 || len(b) != 64 {
		panic("unsafe signing key")
	}
	return ed25519.PrivateKey(b)
}
func main() {
	keys := flag.String("keys", "", "private key directory outside repository")
	in := flag.String("binaries", "build/bundle", "six numbered binaries")
	out := flag.String("out", "", "new immutable release directory")
	seq := flag.Int64("sequence", 0, "monotonic version")
	bootstrapScript := flag.String("bootstrap-script", "install.sh", "reviewed App-pinned bootstrap script")
	origin := flag.String("origin", "https://downloads.potafree.net", "public origin")
	flag.Parse()
	if *keys == "" || *out == "" || *seq <= 0 {
		panic("keys/out/sequence required")
	}
	must(os.MkdirAll(*keys, 0700))
	st, e := os.Stat(*keys)
	must(e)
	if st.Mode().Perm()&0077 != 0 {
		panic("private key directory required")
	}
	if _, e = os.Stat(*out); !os.IsNotExist(e) {
		panic("output must not exist")
	}
	now := time.Now().UTC()
	expiry := now.Add(30 * 24 * time.Hour)
	signers := map[string]signature.Signer{}
	rootPath := filepath.Join(*keys, "root.json")
	rb, e := os.ReadFile(rootPath)
	if e == nil {
		// Existing trust root: the root key is NOT needed (it stays offline;
		// CI only holds targets/snapshot/timestamp/bootstrap). Missing keys
		// must be recovered, never regenerated, and each must match the key
		// root.json trusts for its role.
		root, err := metadata.Root().FromBytes(rb)
		must(err)
		for _, role := range []string{"targets", "snapshot", "timestamp", "bootstrap"} {
			if _, err := os.Stat(filepath.Join(*keys, role+".key")); err != nil {
				panic("Existing trust root: missing " + role + " key must be recovered, not regenerated")
			}
		}
		for _, role := range []string{"targets", "snapshot", "timestamp"} {
			k := key(*keys, role)
			pub, err := metadata.KeyFromPublicKey(k.Public())
			must(err)
			keyID, err := pub.ID()
			must(err)
			trusted := false
			for _, id := range root.Signed.Roles[role].KeyIDs {
				if id == keyID {
					trusted = true
				}
			}
			if !trusted {
				panic(role + " key does not match root.json")
			}
			s, err := signature.LoadSigner(k, crypto.Hash(0))
			must(err)
			signers[role] = s
		}
	} else if os.IsNotExist(e) {
		// First run only: create every key and the trust root.
		root := metadata.Root(now.Add(365 * 24 * time.Hour))
		root.Signed.ConsistentSnapshot = true
		for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
			k := key(*keys, role)
			s, err := signature.LoadSigner(k, crypto.Hash(0))
			must(err)
			signers[role] = s
			pub, err := metadata.KeyFromPublicKey(k.Public())
			must(err)
			must(root.Signed.AddKey(pub, role))
		}
		_, e = root.Sign(signers["root"])
		must(e)
		rb, e = root.ToBytes(false)
		must(e)
		write(rootPath, rb, 0600)
	} else {
		must(e)
	}
	targets := metadata.Targets(expiry)
	targets.Signed.Version = *seq
	manifestTargets := map[string]any{}
	for _, platform := range []string{"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64"} {
		b, err := os.ReadFile(filepath.Join(*in, platform))
		must(err)
		if len(b) == 0 || len(b) > 64*1024*1024 {
			panic("binary size")
		}
		hash := sha256.Sum256(b)
		h := hex.EncodeToString(hash[:])
		name := "agent/" + platform
		target, err := metadata.TargetFile().FromBytes(name, b, "sha256")
		must(err)
		custom, _ := json.Marshal(map[string]any{"sequence": *seq, "apiVersion": 2, "platform": platform})
		r := json.RawMessage(custom)
		target.Custom = &r
		targets.Signed.Targets[name] = target
		file := "targets/agent/" + h + "." + platform
		write(filepath.Join(*out, file), b, 0644)
		manifestTargets[platform] = map[string]any{"sha256": h, "length": len(b), "url": *origin + "/agent/" + file}
	}
	_, e = targets.Sign(signers["targets"])
	must(e)
	tb, e := targets.ToBytes(false)
	must(e)
	snapshot := metadata.Snapshot(expiry)
	snapshot.Signed.Version = *seq
	tf := metadata.MetaFile(*seq)
	th := sha256.Sum256(tb)
	tf.Length = int64(len(tb))
	tf.Hashes = metadata.Hashes{"sha256": th[:]}
	snapshot.Signed.Meta["targets.json"] = tf
	_, e = snapshot.Sign(signers["snapshot"])
	must(e)
	sb, e := snapshot.ToBytes(false)
	must(e)
	timestamp := metadata.Timestamp(expiry)
	timestamp.Signed.Version = *seq
	sf := metadata.MetaFile(*seq)
	sh := sha256.Sum256(sb)
	sf.Length = int64(len(sb))
	sf.Hashes = metadata.Hashes{"sha256": sh[:]}
	timestamp.Signed.Meta["snapshot.json"] = sf
	_, e = timestamp.Sign(signers["timestamp"])
	must(e)
	ts, e := timestamp.ToBytes(false)
	must(e)
	version := strconv.FormatInt(*seq, 10)
	for name, b := range map[string][]byte{"1.root.json": rb, "root.json": rb, "targets.json": tb, version + ".targets.json": tb, "snapshot.json": sb, version + ".snapshot.json": sb, "timestamp.json": ts} {
		write(filepath.Join(*out, "metadata", name), b, 0644)
	}
	policy := map[string]any{"enabled": true, "metadataURL": *origin + "/agent/stable/metadata/", "targetsURL": *origin + "/agent/targets/", "root": json.RawMessage(rb)}
	script, e := os.ReadFile(*bootstrapScript)
	must(e)
	if len(script) == 0 || len(script) > 65536 {
		panic("invalid bootstrap script length")
	}
	scriptHash := sha256.Sum256(script)
	write(filepath.Join(*out, "install.sh"), script, 0644)
	payload, e := json.Marshal(map[string]any{"schema": 1, "sequence": *seq, "expires": expiry.Format(time.RFC3339), "targets": manifestTargets, "updatePolicy": policy, "sshPairing": 1, "bootstrapHash": hex.EncodeToString(scriptHash[:])})
	must(e)
	bootstrap := key(*keys, "bootstrap")
	envelope, _ := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(payload), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(bootstrap, payload))})
	write(filepath.Join(*out, "manifest.json"), envelope, 0644)
	write(filepath.Join(*out, "bootstrap-public-key.txt"), []byte(base64.StdEncoding.EncodeToString(bootstrap.Public().(ed25519.PublicKey))), 0644)
	pb, _ := json.Marshal(policy)
	write(filepath.Join(*out, "update-policy.json"), pb, 0644)
	fmt.Println("Release generated:", *seq, "expires", expiry.Format(time.RFC3339))
}
