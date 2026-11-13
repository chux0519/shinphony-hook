# Shinphony Hook

Shinphony Hook is the host-side part of [Shinphony](https://potafree.net/shinphony):
a small daemon, plus a command-line client, that receives turn and approval
events from coding agents (Claude Code, Codex, DSH) and delivers notifications
through the Shinphony relay to the paired phone.

This repository is the public source for the binaries the Shinphony app
installs. It is published so that anyone can read what runs on their computer,
check the signed release hashes, and rebuild the released binaries.

## What it does

- Runs as the current user; no administrator rights and no global install.
- Talks to local agent hooks over a private Unix socket (named pipe on Windows).
- Stores its queue and settings in SQLite under `~/.shinphony-agent` (mode 0700)
  and keeps notification credentials read-only from the existing
  `~/.shinphony-notify` store.
- Never opens a network listener, never exposes a remote shell, and never stores
  terminal output or chat content.
- Verifies the signed release metadata (TUF, pinned root in `deploy/root.json`)
  before installing or updating a binary.
- Delivers notifications through the push relay; the relay sees notification
  metadata, not the contents of the user's terminal.

## Repository layout

| Path | Contents |
| --- | --- |
| `*.go`, `internal/` | the Hook daemon and CLI, agent hook installers, local IPC, queue and SQLite store |
| `cmd/release` | offline release signer (private keys never enter the repository) |
| `cmd/verifyrelease` | release and metadata verifier using the pinned root |
| `deploy/` | the pinned TUF root and bootstrap public key |
| `site/` | the `shinphony.app` Worker behind `/pair` and `/hook` |
| `worker/` | the Cloudflare push relay Worker |
| `server/` | shared relay cores used by `worker/` (the retired VPS entrypoints are not published) |
| `tool/` | build, release verification and export tooling |
| `docs/` | architecture and verification notes |

## Build and test

The Go version is pinned exactly in `go.mod`; CI reads that line, and a local Go
newer than the pin uses it through `GOTOOLCHAIN`. The Hook builds with
`CGO_ENABLED=0`.

```sh
make build                                   # build/shinphony-hook
go test ./...                                # Go tests
go vet ./...
cd site && npm ci && node --test            # Worker tests
cd site && sh test/pair_test.sh              # /pair script tests
```

`tool/bundle.sh <dir>` builds the six release targets with the release flags
(`-trimpath`, `-buildvcs=false`, stripped, sequence stamped into the binary) and
writes their hashes. It does not publish anything.

## Verify a release

- Browse <https://shinphony.app/hook> for the current sequence, release date and
  the signed SHA-256 of every platform.
- `shasum -a 256 ~/.shinphony-agent/shinphony-hook-*` (or `sha256sum` on Linux)
  checks the binary that is installed.
- `tool/verify_reproducible.sh <sequence>` rebuilds all six targets in a clean
  Go cache and compares them with the signed metadata. See
  [docs/verify.md](docs/verify.md).

Releases published before the `-buildvcs=false` change embedded the git commit
in the binary, so they cannot be reproduced from a different checkout. Their
hashes are still authentic; only the rebuild comparison is expected to differ.

## Security

Please read [SECURITY.md](SECURITY.md) before reporting a vulnerability.

## License

Apache License 2.0; see [LICENSE](LICENSE).