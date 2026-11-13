# Verifying a Shinphony Hook release

This note explains what the published hashes mean and how to check a binary or
rebuild it from source.

## Trust chain

1. The app ships a pinned bootstrap public key. The Hook ships the pinned TUF
   root in `deploy/root.json`.
2. The release workflow signs `targets.json`, `snapshot.json` and
   `timestamp.json` with keys that the root trusts. It then signs a manifest
   with the bootstrap key.
3. `cmd/verifyrelease` checks signatures, expiry, versions, declared hashes and
   lengths. The installer and updater verify the same metadata before using a
   binary.
4. The app checks the downloaded binary against the signed SHA-256 before
   installing it under `~/.shinphony-agent/shinphony-hook-<sha256>`.

A hash on its own is not a trust root; only the signatures over the metadata
are.

## Check the hashes on the page

<https://shinphony.app/hook> shows the current sequence, its release date and
the signed SHA-256 of every platform. The page is plain HTML with no JavaScript
and is built from verified metadata only. If verification fails it shows no
hashes.

## Check an installed binary

macOS:

```sh
shasum -a 256 ~/.shinphony-agent/shinphony-hook-*
```

Linux:

```sh
sha256sum ~/.shinphony-agent/shinphony-hook-*
```

The file name contains the same hash it should have, and the output must match
the entry for your platform on `/hook`.

## Rebuild and compare

From a checkout of this repository, with the Go version pinned in `go.mod`:

```sh
tool/verify_reproducible.sh <sequence>
```

The script:

1. fetches the published TUF metadata from
   `https://downloads.potafree.net/agent/stable/metadata`,
2. verifies it against `deploy/root.json` with
   `go run ./cmd/verifyrelease --metadata-url ... --pinned-root-file ...`,
3. rebuilds all six targets in a fresh temporary `GOPATH` and `GOCACHE` with
   the release flags (`CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`,
   `-ldflags="-s -w -X main.releaseSequence=<sequence>"`),
4. prints `MATCH` or `MISMATCH` per target and exits non-zero on a mismatch.

The first run downloads the module cache into the temporary GOPATH. For a
staging or local metadata origin, set `SHINPHONY_METADATA_URL`.

`build/reproducible/verified.json` (the verified metadata) and `result.txt`
(the comparison) are left behind for inspection; `build/` is git-ignored.

## Expected mismatch on old releases

Releases built before the `-buildvcs=false` change let Go embed the git commit
into the binary. A rebuild from a different checkout therefore produces a
different hash even with identical sources. Such a mismatch does **not** mean
the downloaded binary is wrong: the signed hash is still authentic and the
installed binary still matches it. Only the rebuild comparison is affected.

Releases built with the current `tool/bundle.sh` are reproducible from the
same source tree and toolchain. Sequence 2026111303 predates the change, so a
rebuild of it is expected to differ; later sequences are built without VCS
stamping.